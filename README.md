# Lightriver Automated Multivendor Inventory System

Network Inventory program for the Nokia 7705/7250/1830 devices.

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Usage](#usage)
- [Building Executable](#building-executable)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

## Overview

The Network Inventory program is designed to manage inventory for 7705/7250 devices. It supports gathering data over both network and serial connections, processing the data, and generating inventory reports. Additionally, the program can create packing slips for each device.

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/Chees3loaf/Network-Inventory-Update.git
   cd Network-Inventory-Update
   ```

2. **Create a virtual environment (optional but recommended):**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install the required packages:**

   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. **Run the GUI:**

   ```bash
   python main.py
   ```

2. **Program Flow:**
   - The GUI allows you to configure the network or serial connection details.
   - After setting the required parameters, you can execute the script to gather inventory data.
   - You will be prompted to save the inventory data to a specified location.
   - If updates are available, you will be notified and given the option to apply them.
   - You can also generate packing slips after the inventory data is collected.

## Building Executable

To deploy the program as an executable on the target OS, follow these steps:

1. **Install the required packages:**

   ```bash
   pip install -r requirements.txt
   ```

2. **Use PyInstaller to build the executable:**

   ```bash
   pyinstaller --noconsole --name "NetworkInventory" --onefile main.py
   ```

This will create a standalone executable in the `dist` directory.

## Project Structure

```bash
Network-Inventory/
│
├── main.py                  # Entry point for the application
├── requirements.txt         # List of required packages
├── gui/
│   └── gui3_0.py            # Main GUI script
│
├── scripts/
│   ├── __pycache__/         # Compiled Python files
│   ├── Lightriver packing slip.xlsx  # Packing slip template
│   ├── Nokia_7705_7250.py   # Script for 7705/7250 devices
│   ├── packing_slip.py      # Script for generating packing slips
│   └── script_interface.py  # Interface for device scripts
│
└── utils/
    ├── network_inventory.db # SQLite database for part numbers
    └── update.py            # Update management script
```

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/your-feature`).
3. Commit your changes (`git commit -am 'Add new feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Create a new Pull Request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
