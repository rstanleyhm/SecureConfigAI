import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def log_findings(findings):
    if findings:
        for finding in findings:
            logging.warning(f"Rule {finding[0]}: {finding[1]} (Severity: {finding[2]})")
    else:
        logging.info("No security issues detected.")
