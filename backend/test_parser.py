from app.services.log_ingestion import parse_log_line


with open("../sample_logs/auth.log", "r") as file:
    for line in file:
        event = parse_log_line(line.strip())

        if event:
            print(event)
