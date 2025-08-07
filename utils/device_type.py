import logging
import time
import paramiko
import re
import telnetlib
from queue import Queue
from paramiko.ssh_exception import AuthenticationException
from scripts.Nokia_SAR import Script as Sar
from scripts.Nokia_IXR import Script as Ixr
from scripts.Nokia_1830 import Script as Pss

# Configure logging with a debug flag
debug_mode = False  # Toggle this for verbose logging
logging.basicConfig(level=logging.DEBUG if debug_mode else logging.INFO)

class DeviceIdentifier:
    def __init__(self, username='admin', password='admin'):
        self.username = username
        self.password = password

    def identify_device(self, ip, queue):
        logging.debug(f"Attempting SSH device ID at {ip}")
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=self.username, password=self.password, look_for_keys=False, allow_agent=False, timeout=10)

            session = ssh.invoke_shell()
            time.sleep(1)
            session.send("show chassis | match (Type) pre-lines 1 expression\n")
            time.sleep(2)

            output = ""
            end_time = time.time() + 3
            while time.time() < end_time:
                if session.recv_ready():
                    output += session.recv(1024).decode('utf-8')
                else:
                    time.sleep(0.1)

            queue.put(f"Response from {ip} (SSH primary):\n{output}")
            logging.debug(output)

            device_type, device_name, product_type = self.parse_device_info(output)
            if device_type or product_type:
                ssh.close()
                return device_type or product_type, device_name, product_type

            session.send("show general system-identification\n")
            time.sleep(2)

            fallback_output = ""
            while session.recv_ready():
                fallback_output += session.recv(1024).decode('utf-8')

            queue.put(f"Response from {ip} (SSH fallback):\n{fallback_output}")
            logging.debug(fallback_output)
            ssh.close()
            return self.parse_device_info(fallback_output)

        except AuthenticationException as ae:
            logging.warning(f"SSH authentication failed for {ip}: {ae}. Triggering Telnet fallback.")
            return self.identify_device_telnet(ip, queue)
        except Exception as e:
            logging.warning(f"SSH failed for {ip}: {e}, trying Telnet...")
            return self.identify_device_telnet(ip, queue)

    def identify_device_telnet(self, ip, queue):
        try:
            tn = telnetlib.Telnet(ip, timeout=10)

            if not self.telnet_login(tn):
                tn.close()
                return None, None, None

            tn.write(b"show general system-identification\n")
            time.sleep(3)
            output = tn.read_until(b"#", timeout=10).decode('ascii')
            tn.write(b"exit\n")
            tn.close()

            queue.put(f"Response from {ip} (Telnet):\n{output}")
            logging.debug(output)
            return self.parse_device_info(output)

        except Exception as e:
            logging.error(f"Telnet failed for {ip}: {e}")
            return None, None, None

    def telnet_login(self, tn: telnetlib.Telnet) -> bool:
        # Handles Telnet login process
        try:
            tn.read_until(b"login: ", timeout=5)
            tn.write(b"cli\n")
            tn.read_until(b"Username: ", timeout=5)
            tn.write(self.username.encode('ascii') + b"\n")
            tn.read_until(b"Password: ", timeout=5)
            tn.write(self.password.encode('ascii') + b"\n")
            time.sleep(1)
            response = tn.read_very_eager().decode('ascii')
            if "Login incorrect" in response or "invalid" in response.lower():
                logging.error("Telnet login failed: Invalid credentials.")
                return False
            logging.info("Telnet login successful.")
            return True
        except Exception as e:
            logging.error(f"Telnet login failed: {e}")
            return False

    @staticmethod
    def parse_device_info(output):
        
        # Extracts data from the command outputs
        
        try:
            type_match = re.search(r"Type\s+:\s+(.+)", output)
            name_match = re.search(r"Name\s+:\s+(.+)", output)
            product_match = re.search(r"Product\s+:\s+(\d+)", output)

            device_type = type_match.group(1).strip() if type_match else None
            device_name = name_match.group(1).strip() if name_match else None
            product_type = product_match.group(1).strip() if product_match else None

            if not (device_type or product_type):
                logging.warning(f"Incomplete device info found in output: {output}")

            return device_type, device_name, product_type
        except Exception as e:
            logging.error(f"Error parsing device info: {e}")
            return None, None, None


class ScriptSelector:
    DEVICE_SCRIPT_MAPPING = {
        '7705 sar-8 v2': Sar,
        '7250 ixr-r6': Ixr,
        '7250 ixr-r6d': Ixr,
        '1830': Pss,
    }

    def select_script(self, device_type, connection_type='ssh'):
        
        # Select a script class based on device type and connection type.
        
        normalized_device_type = device_type.strip().lower() if device_type else 'unknown'
        script_class = self.DEVICE_SCRIPT_MAPPING.get(normalized_device_type)
        
        if script_class:
            logging.debug(f"Script class for device type '{device_type}': {script_class.__name__}")
            return script_class
        else:
            logging.error(f"No script found for device type: '{device_type}'")
            return None
