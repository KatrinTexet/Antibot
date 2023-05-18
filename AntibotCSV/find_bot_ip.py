import csv


def open_csw(name_csv: str):
    rows = []
    with open(name_csv) as logs:
        reader = csv.reader(logs)
        for row in reader:
            rows.append(row)
    fields = rows[0]
    rows = rows[1:]
    return fields, rows


def frequencies_ip(fields, rows):
    index_ip = fields.index('ip')
    frequencies = {}
    for row in rows:
        id = row[index_ip]
        if id not in frequencies:
            frequencies[id] = 1
        else:
            frequencies[id] += 1
    return frequencies


def last_row_max_ip(fields, rows, max_ip):
    index_ip = fields.index('ip')
    index_user = fields.index('user-agent')
    index_timestamp = fields.index('timestamp')
    for row in reversed(rows):
        if row[index_ip] == max_ip:
            user_agent, timestamp = row[index_user], row[index_timestamp]
            return user_agent, timestamp


def anti_bot_found_ip():
    fields, rows = open_csw("m5-access-log-all.csv")
    frequencies = frequencies_ip(fields, rows)
    count_max_ip = max(frequencies.values())
    max_ip = max(frequencies, key=frequencies.get)
    all_ip = len(frequencies)
    percentage_max_ip = count_max_ip * 100 / all_ip
    user_agent_max_ip, timestamp_max_ip = last_row_max_ip(fields, rows, max_ip)
    suspicious_agent = {
        "ip": max_ip,
        "fraction": percentage_max_ip,
        "count": frequencies[max_ip],
        "last": {
            "agent": user_agent_max_ip,
            "timestamp": timestamp_max_ip
        }
    }

    return suspicious_agent


print(anti_bot_found_ip())
