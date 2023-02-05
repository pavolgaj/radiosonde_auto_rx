#!/usr/bin/env python
#
#   Radiosonde Auto RX Service - V2.0
#
#   Copyright (C) 2018  Mark Jessop <vk5qi@rfhead.net>
#   Released under GNU GPL v3 or later
#
#   Refer github page for instructions on setup and usage.
#   https://github.com/projecthorus/radiosonde_auto_rx/
#
import argparse
import datetime
import logging
import re
import sys
import time
import traceback
import os
from dateutil.parser import parse
from queue import Queue

if sys.version_info < (3, 6):
    print("CRITICAL - radiosonde_auto_rx requires Python 3.6 or newer!")
    sys.exit(1)

import autorx
from autorx.scan import SondeScanner
from autorx.decode import SondeDecoder, VALID_SONDE_TYPES, DRIFTY_SONDE_TYPES
from autorx.logger import TelemetryLogger
from autorx.email_notification import EmailNotification
from autorx.habitat import HabitatUploader
from autorx.aprs import APRSUploader
from autorx.ozimux import OziUploader
from autorx.sondehub import SondehubUploader
from autorx.rotator import Rotator
from autorx.utils import (
    rtlsdr_test,
    position_info,
    check_rs_utils,
    version_startup_check,
)
from autorx.config import read_auto_rx_config
from autorx.web import (
    start_flask,
    stop_flask,
    flask_emit_event,
    WebHandler,
    WebExporter,
)
from autorx.gpsd import GPSDAdaptor
from autorx.sdr_wrappers import shutdown_sdr


# Logging level
# INFO = Basic status messages
# DEBUG = Adds detailed information on submodule operations.
logging_level = logging.INFO


#
#   Global Variables
#

RS_PATH = "./"

# Optional override for RS92 ephemeris data.
rs92_ephemeris = None

# Global configuration dictionary. Populated on startup.
config = None

# Exporter Lists
exporter_objects = (
    []
)  # This list will hold references to each exporter instance that is created.
exporter_functions = (
    []
)  # This list will hold references to the exporter add functions, which will be passed onto the decoders.

# Separate reference to the e-mail exporter, as we may want to use this for error notifications.
email_exporter = None

# GPSDAdaptor Instance, if used.
gpsd_adaptor = None

# Temporary frequency block list
# This contains frequncies that should be blocked for a short amount of time.
temporary_block_list = {}



def clean_task_list():
    """Check the task list to see if any tasks have stopped running. If so, release the associated SDR"""

    for _key in autorx.task_list.copy().keys():
        # Attempt to get the state of the task
        try:
            _running = autorx.task_list[_key]["task"].running()
            _task_sdr = autorx.task_list[_key]["device_idx"]
            _exit_state = autorx.task_list[_key]["task"].exit_state
        except Exception as e:
            logging.error(
                "Task Manager - Error getting task %s state - %s" % (str(_key), str(e))
            )
            continue

        if _running == False:
            # This task has stopped.
            # Check the exit state of the task for any abnormalities:
            if (_exit_state == "Encrypted") or (_exit_state == "TempBlock"):
                # This task was a decoder, and it has encountered an encrypted sonde, or one too far away.
                logging.info(
                    "Task Manager - Adding temporary block for frequency %.3f MHz"
                    % (_key / 1e6)
                )
                # Add the sonde's frequency to the global temporary block-list
                temporary_block_list[_key] = time.time()
                # If there is a scanner currently running, add it to the scanners internal block list.
                if "SCAN" in autorx.task_list:
                    autorx.task_list["SCAN"]["task"].add_temporary_block(_key)

            if _exit_state == "FAILED SDR":
                # The SDR was not able to be recovered after many attempts.
                # Remove it from the SDR list and flag an error.
                autorx.sdr_list.pop(_task_sdr)
                _error_msg = (
                    "Task Manager - Removed SDR %s from SDR list due to repeated failures."
                    % (str(_task_sdr))
                )
                logging.error(_error_msg)

                # Send email if configured.
                email_error(_error_msg)

            else:
                # Release its associated SDR.
                autorx.sdr_list[_task_sdr]["in_use"] = False
                autorx.sdr_list[_task_sdr]["task"] = None

            # Pop the task from the task list.
            autorx.task_list.pop(_key)
            # Indicate to the web client that the task list has been updated.
            flask_emit_event("task_event")

    # Clean out the temporary block list of old entries.
    for _freq in temporary_block_list.copy().keys():
        if temporary_block_list[_freq] < (
            time.time() - config["temporary_block_time"] * 60
        ):
            temporary_block_list.pop(_freq)
            logging.info(
                "Task Manager - Removed %.3f MHz from temporary block list."
                % (_freq / 1e6)
            )

    # Check if there is a scanner thread still running.
    # If not, and if there is a SDR free, start one up again.
    # Also check for a global scan inhibit flag.
    if (
        ("SCAN" not in autorx.task_list)
        and (not autorx.scan_inhibit)
        and (allocate_sdr(check_only=True) is not None)
    ):
        # We have a SDR free, and we are not running a scan thread. Start one.
        start_scanner()


def stop_all():
    """Shut-down all decoders, scanners, and exporters."""
    global exporter_objects
    logging.info("Starting shutdown of all threads.")
    for _task in autorx.task_list.keys():
        try:
            autorx.task_list[_task]["task"].stop()
        except Exception as e:
            logging.error("Error stopping task - %s" % str(e))

    for _exporter in exporter_objects:
        try:
            _exporter.close()
        except Exception as e:
            logging.error("Error stopping exporter - %s" % str(e))

    if gpsd_adaptor != None:
        gpsd_adaptor.close()


def telemetry_filter(telemetry):
    """Filter incoming radiosonde telemetry based on various factors,
        - Invalid Position
        - Invalid Altitude
        - Abnormal range from receiver.
        - Invalid serial number.
        - Abnormal date (more than 6 hours from utcnow)

    This function is defined within this script to avoid passing around large amounts of configuration data.

    """
    global config

    # First Check: zero lat/lon
    if (telemetry["lat"] == 0.0) and (telemetry["lon"] == 0.0):
        logging.warning(
            "Zero Lat/Lon. Sonde %s does not have GPS lock." % telemetry["id"]
        )
        return False

    # Second check: Altitude cap.
    if telemetry["alt"] > config["max_altitude"]:
        _altitude_breach = telemetry["alt"] - config["max_altitude"]
        logging.warning(
            "Sonde %s position breached altitude cap by %d m."
            % (telemetry["id"], _altitude_breach)
        )
        return False

    # Third check: Number of satellites visible.
    if "sats" in telemetry:
        if telemetry["sats"] < 4:
            logging.warning(
                "Sonde %s can only see %d GNSS sats - discarding position as bad."
                % (telemetry["id"], telemetry["sats"])
            )
            return False

    # Fourth check - is the payload more than x km from our listening station.
    # Only run this check if a station location has been provided.
    if (config["station_lat"] != 0.0) and (config["station_lon"] != 0.0):
        # Calculate the distance from the station to the payload.
        _listener = (
            config["station_lat"],
            config["station_lon"],
            config["station_alt"],
        )
        _payload = (telemetry["lat"], telemetry["lon"], telemetry["alt"])
        # Calculate using positon_info function from rotator_utils.py
        _info = position_info(_listener, _payload)

        if _info["straight_distance"] > config["max_radius_km"] * 1000:
            _radius_breach = (
                _info["straight_distance"] / 1000.0 - config["max_radius_km"]
            )
            logging.warning(
                "Sonde %s position breached radius cap by %.1f km."
                % (telemetry["id"], _radius_breach)
            )

            if config["radius_temporary_block"]:
                logging.warning(
                    "Blocking for %d minutes." % config["temporary_block_time"]
                )
                return "TempBlock"
            else:
                return False

        if (_info["straight_distance"] < config["min_radius_km"] * 1000) and config[
            "radius_temporary_block"
        ]:
            logging.warning(
                "Sonde %s within minimum radius limit (%.1f km). Blocking for %d minutes."
                % (
                    telemetry["id"],
                    config["min_radius_km"],
                    config["temporary_block_time"],
                )
            )
            return "TempBlock"

    # DateTime Check
    _delta_time = (
        datetime.datetime.now(datetime.timezone.utc) - parse(telemetry["datetime"])
    ).total_seconds()
    logging.debug("Delta time: %d" % _delta_time)

    if abs(_delta_time) > (3600 * config["sonde_time_threshold"]):
        logging.warning(
            "Sonde reported time too far from current UTC time. Either sonde time or system time is invalid. (Threshold: %d hours)"
            % config["sonde_time_threshold"]
        )
        return False

    # Payload Serial Number Checks
    _serial = telemetry["id"]
    # Run a Regex to match known Vaisala RS92/RS41 serial numbers (YWWDxxxx)
    # RS92: https://www.vaisala.com/sites/default/files/documents/Vaisala%20Radiosonde%20RS92%20Serial%20Number.pdf
    # RS41: https://www.vaisala.com/sites/default/files/documents/Vaisala%20Radiosonde%20RS41%20Serial%20Number.pdf
    # This will need to be re-evaluated if we're still using this code in 2021!
    # UPDATE: Had some confirmation that Vaisala will continue to use the alphanumeric numbering up until
    # ~2025-2030, so have expanded the regex to match (and also support some older RS92s)
    # Modified 2021-06 to be more flexible and match older sondes, and reprogrammed sondes.
    # Still needs a letter at the start, but the numbers don't need to match the format exactly.
    vaisala_callsign_valid = re.match(r"[C-Z][\d][\d][\d]\d{4}", _serial)

    # Just make sure we're not getting the 'xxxxxxxx' unknown serial from the DFM decoder.
    if "DFM" in telemetry["type"]:
        dfm_callsign_valid = "x" not in _serial.split("-")[1]
    else:
        dfm_callsign_valid = False

    # Check Meisei sonde callsigns for validity.
    # meisei_ims returns a callsign of IMS100-xxxxxx until it receives the serial number, so we filter based on the x's being present or not.
    if "MEISEI" in telemetry["type"] or "IMS100" in telemetry["type"] or "RS11G" in telemetry["type"]:
        meisei_callsign_valid = "x" not in _serial.split("-")[1]
    else:
        meisei_callsign_valid = False

    if "MRZ" in telemetry["type"]:
        mrz_callsign_valid = "x" not in _serial.split("-")[1]
    else:
        mrz_callsign_valid = False

    # If Vaisala or DFMs, check the callsigns are valid. If M10/M20, iMet, MTS01 or LMS6, just pass it through - we get callsigns immediately and reliably from these.
    if (
        vaisala_callsign_valid
        or dfm_callsign_valid
        or meisei_callsign_valid
        or mrz_callsign_valid
        or ("M10" in telemetry["type"])
        or ("M20" in telemetry["type"])
        or ("LMS" in telemetry["type"])
        or ("IMET" in telemetry["type"])
        or ("MTS01" in telemetry["type"])
    ):
        return "OK"
    else:
        _id_msg = "Payload ID %s is invalid." % telemetry["id"]
        # Add in a note about DFM sondes and their oddness...
        if "DFM" in telemetry["id"]:
            _id_msg += " Note: DFM sondes may take a while to get an ID."

        if "MRZ" in telemetry["id"]:
            _id_msg += " Note: MRZ sondes may take a while to get an ID."

        logging.warning(_id_msg)
        return False


def station_position_update(position):
    """Handle a callback from GPSDAdaptor object, and update each exporter object."""
    global exporter_objects
    # Quick sanity check of the incoming data
    if "valid" not in position:
        return

    for _exporter in exporter_objects:
        try:
            _exporter.update_station_position(
                position["latitude"], position["longitude"], position["altitude"]
            )
        except AttributeError:
            # This exporter does not require station position data.
            pass
        except Exception as e:
            traceback.print_exc()
            logging.error("Error updating exporter station position.")


def email_error(message="foo"):
    """Helper function to email an error message, if the email exporter is available"""
    global email_exporter

    if email_exporter and config["email_error_notifications"]:
        try:
            email_exporter.send_notification_email(message=message)
        except Exception as e:
            logging.error("Error attempting to send notification email: %s" % str(e))
    else:
        logging.debug("Not sending Email notification, as Email not configured.")


def main():
    """Main Loop"""
    global config, exporter_objects, exporter_functions, logging_level, rs92_ephemeris, gpsd_adaptor, email_exporter

    # Command line arguments.
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--config",
        default="station.cfg",
        help="Receive Station Configuration File. Default: station.cfg",
    )
    parser.add_argument(
        "-l",
        "--log",
        default="./log/",
        help="Receive Station Log Path. Default: ./log/",
    )
    parser.add_argument(
        "-f",
        "--frequency",
        type=float,
        default=0.0,
        help="Sonde Frequency Override (MHz). This overrides the only_scan list with the supplied frequency.",
    )
    parser.add_argument(
        "-m",
        "--type",
        type=str,
        default=None,
        help="Immediately start a decoder for a provided sonde type (Valid Types: RS41, RS92, DFM, M10, M20, IMET, IMET5, LMS6, MK2LMS, MEISEI, MRZ)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=0,
        help="Close auto_rx system after N minutes. Use 0 to run continuously.",
    )
    parser.add_argument(
        "-v", "--verbose", help="Enable debug output.", action="store_true"
    )
    parser.add_argument(
        "-e",
        "--ephemeris",
        type=str,
        default="None",
        help="Use a manually obtained ephemeris file when decoding RS92 Sondes.",
    )
    parser.add_argument(
        "--systemlog",
        action="store_true",
        default=False,
        help="Write a auto_rx system log-file to ./log/ (default=False)",
    )
    args = parser.parse_args()

    # Copy out timeout value, and convert to seconds,
    _timeout = args.timeout * 60

    # Copy out RS92 ephemeris value, if provided.
    if args.ephemeris != "None":
        rs92_ephemeris = args.ephemeris

    # Set log-level to DEBUG if requested
    if args.verbose:
        logging_level = logging.DEBUG

    # Define the default logging path
    logging_path = "./log/"

    # Validate the user supplied log path
    if os.path.isdir(args.log):
        logging_path = os.path.abspath(args.log)
    else:
        # Using print because logging may not be established yet
        print("Invalid logging path, using default. Does the folder exist?")

    # Update Global logging path, used by other modules.
    autorx.logging_path = logging_path

    # Configure logging
    _log_suffix = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S_system.log")
    _log_path = os.path.join(logging_path, _log_suffix)

    system_log_enabled = False

    if args.systemlog:
        # Only write out a logs to a system log file if we have been asked to.
        # Systemd will capture and logrotate our logs anyway, so writing to our own log file is less useful.
        logging.basicConfig(
            format="%(asctime)s %(levelname)s:%(message)s",
            filename=_log_path,
            level=logging_level,
        )
        logging.info("Opened new system log file: %s" % _log_path)
        # Also add a separate stdout logger.
        stdout_format = logging.Formatter("%(asctime)s %(levelname)s:%(message)s")
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setFormatter(stdout_format)
        logging.getLogger().addHandler(stdout_handler)
        system_log_enabled = True
    else:
        # Otherwise, we only need the stdout logger, which if we don't specify a filename to logging.basicConfig,
        # is the default...
        logging.basicConfig(
            format="%(asctime)s %(levelname)s:%(message)s", level=logging_level
        )


    # Set the requests/socketio loggers (and related) to only display critical log messages.
    logging.getLogger("requests").setLevel(logging.CRITICAL)
    logging.getLogger("urllib3").setLevel(logging.CRITICAL)
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    logging.getLogger("socketio").setLevel(logging.ERROR)
    logging.getLogger("engineio").setLevel(logging.ERROR)
    logging.getLogger("geventwebsocket").setLevel(logging.ERROR)

    # Attempt to read in config file
    logging.info("Reading configuration file...")
    _temp_cfg = read_auto_rx_config(args.config,no_sdr_test=True)
    if _temp_cfg is None:
        logging.critical("Error in configuration file! Exiting...")
        sys.exit(1)
    else:
        config = _temp_cfg
        #autorx.sdr_list = config["sdr_settings"]

    # Check all the RS utilities exist.
    if not check_rs_utils():
        sys.exit(1)

    # If a sonde type has been provided, insert an entry into the scan results,
    # and immediately start a decoder. This also sets the decoder time to 0, which
    # allows it to run indefinitely.
    

    # Start up the flask server.
    # This needs to occur AFTER logging is setup, else logging breaks horribly for some reason.
    start_flask(host=config["web_host"], port=config["web_port"])

    # If we have been supplied a frequency via the command line, override the only_scan list settings
    # to only include the supplied frequency.

    # Start our exporter options
    # Telemetry Logger

    if config["email_enabled"]:

        _email_notification = EmailNotification(
            smtp_server=config["email_smtp_server"],
            smtp_port=config["email_smtp_port"],
            smtp_authentication=config["email_smtp_authentication"],
            smtp_login=config["email_smtp_login"],
            smtp_password=config["email_smtp_password"],
            mail_from=config["email_from"],
            mail_to=config["email_to"],
            mail_subject=config["email_subject"],
            mail_nearby_landing_subject=config["email_nearby_landing_subject"],
            station_position=(
                config["station_lat"],
                config["station_lon"],
                config["station_alt"],
            ),
            launch_notifications=config["email_launch_notifications"],
            landing_notifications=config["email_landing_notifications"],
            landing_range_threshold=config["email_landing_range_threshold"],
            landing_altitude_threshold=config["email_landing_altitude_threshold"],
        )
        email_exporter = _email_notification

        exporter_objects.append(_email_notification)
        exporter_functions.append(_email_notification.add)

    # Habitat Uploader - DEPRECATED - Sondehub DB now in use (>1.5.0)
    # if config["habitat_enabled"]:

    #     if config["habitat_upload_listener_position"] is False:
    #         _habitat_station_position = None
    #     else:
    #         _habitat_station_position = (
    #             config["station_lat"],
    #             config["station_lon"],
    #             config["station_alt"],
    #         )

    #     _habitat = HabitatUploader(
    #         user_callsign=config["habitat_uploader_callsign"],
    #         user_antenna=config["habitat_uploader_antenna"],
    #         station_position=_habitat_station_position,
    #         synchronous_upload_time=config["habitat_upload_rate"],
    #         callsign_validity_threshold=config["payload_id_valid"],
    #         url=config["habitat_url"],
    #     )

    #     exporter_objects.append(_habitat)
    #     exporter_functions.append(_habitat.add)

    # APRS Uploader
    

    _web_exporter = WebExporter(max_age=config["web_archive_age"])
    exporter_objects.append(_web_exporter)
    exporter_functions.append(_web_exporter.add)

    # GPSD Startup
    if config["gpsd_enabled"]:
        gpsd_adaptor = GPSDAdaptor(
            hostname=config["gpsd_host"],
            port=config["gpsd_port"],
            callback=station_position_update,
        )

    version_startup_check()

    # Note the start time.
    _start_time = time.time()



    # Loop.
    while True:
        # Check for finished tasks.
        # Handle any new scan results.
        #handle_scan_results()
        # Sleep a little bit.
        time.sleep(2)

        

        # Allow a timeout after a set time, for users who wish to run auto_rx
        # within a cronjob.
        if (_timeout > 0) and ((time.time() - _start_time) > _timeout):
            logging.info("Shutdown time reached. Closing.")
            stop_flask(host=config["web_host"], port=config["web_port"])
            stop_all()
            break


if __name__ == "__main__":

    try:
        main()
    except KeyboardInterrupt:
        # Upon CTRL+C, shutdown all threads and exit.
        stop_flask(host=config["web_host"], port=config["web_port"])
        stop_all()
    except Exception as e:
        # Upon exceptions, attempt to shutdown threads and exit.
        traceback.print_exc()
        print("Main Loop Error - %s" % str(e))
        stop_flask(host=config["web_host"], port=config["web_port"])
        stop_all()
