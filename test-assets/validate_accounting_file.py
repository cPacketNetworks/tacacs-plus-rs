#!/usr/bin/env python3

from datetime import datetime, timezone, timedelta
import sys

# structure of log record (shrubbery daemon):
# timestamp <tab> IP <tab> user <tab> port <tab> remote_addr <tab> (start | stop | update) <tab> arguments*

# there should be 3 records/lines in the accounting file
EXPECTED_FILE_LINES = 3

# strptime timestamp format
TIMESTAMP_FORMAT = "%b %d %H:%M:%S"

NOW = datetime.now()
# timestamps are UTC in the logs, so we have to account for that
parse_timestamp = lambda timestamp: datetime.strptime(timestamp, TIMESTAMP_FORMAT).replace(year=NOW.year, tzinfo=timezone.utc)

# indices of various record components
TIMESTAMP_INDEX = 0
IP_INDEX = 1
USER_INDEX = 2
PORT_INDEX = 3
REMOTE_ADDR_INDEX = 4
RECORD_TYPE_INDEX = 5
TASK_ID_INDEX = 6  # always first argument in our case
OTHER_ARGUMENTS_START = 7  # other arguments go after task id

COMMON_INDICES = [IP_INDEX, USER_INDEX, PORT_INDEX, REMOTE_ADDR_INDEX, TASK_ID_INDEX]
get_common_fields = lambda record: [record[i] for i in COMMON_INDICES]

def validate_record(record: list[str], common_fields: list[str], record_type: str, arguments: list[str]):
    assert get_common_fields(record) == common_fields
    assert record[RECORD_TYPE_INDEX] == record_type
    assert record[OTHER_ARGUMENTS_START:] == arguments

if __name__ == "__main__":
    accounting_file_path = sys.argv[1]

    with open(accounting_file_path) as file:
        # replace is due to TACACS+ NG not handling tab separators between arguments properly
        records = [[field.strip() for field in line.replace("\\011", "\t").split("\t")] for line in file]

    assert len(records) == EXPECTED_FILE_LINES

    # first record: start record
    start_record = records[0]
    common_fields = get_common_fields(start_record)

    start_time = parse_timestamp(start_record[0])
    start_time_arg_value = start_record[OTHER_ARGUMENTS_START].split("=")[1]
    start_time_arg = datetime.fromtimestamp(int(start_time_arg_value), tz=timezone.utc)

    # allow for a couple seconds of leeway due to timing weirdness
    assert (start_time_arg - start_time).seconds <= 1

    validate_record(start_record, common_fields, "start", [
        f"start_time={start_time_arg_value}",
        "custom=something"
    ])

    # second record: watchdog update
    update_record = records[1]

    # the shrubbery TACACS+ daemon treats the accounting body flags different than RFC8907,
    # so the packet gets treated like a start packet rather than an update one
    validate_record(update_record, common_fields, "start", [
        "elapsed_time=1",
        "custom2*"  # optional argument
    ])

    # final record: stop
    stop_record = records[2]
    stop_time = parse_timestamp(stop_record[TIMESTAMP_INDEX])

    # again allow for a bit of leeway; this should be 2 seconds but timing is fuzzy
    assert stop_time > start_time_arg and stop_time < start_time_arg + timedelta(seconds=3)

    validate_record(stop_record, common_fields, "stop", [
        # 2 seconds of wait are artificially introduced into test
        f"stop_time={int(stop_time.timestamp())}"
    ])
