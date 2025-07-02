# Bulk Tinder Profile Creator

## Description
**Bulk Tinder Profile Creator** is a powerful Tinder automation script (a Tinder bot) that enables **bulk account creation** and profile generation on Tinder with minimal manual effort. It streamlines the entire Tinder signup process by automating everything from phone number verification (OTP) to uploading profile photos and setting up profile details. This tool is designed for efficiency and can help developers, testers, or growth hackers create multiple Tinder profiles quickly. By simulating the official app's onboarding steps through code, this profile generator saves time and ensures a consistent setup for each account.

## Features
- **End-to-End Tinder Account Automation**: Fully automates the Tinder registration process, acting as a Tinder bot that handles account creation from start to finish (phone verification, profile setup, etc.).  
- **Bulk Profile Creation**: Allows you to create Tinder profiles in bulk. You can run the script repeatedly to generate as many accounts as needed, each with unique credentials and saved session data.  
- **Phone OTP Verification**: Integrates Tinder’s SMS verification flow by sending a code to your phone number and prompting for the OTP. The script automatically submits the OTP to Tinder’s API for you, streamlining the verification step.  
- **Profile Details Setup**: Automates entering profile information such as name, date of birth, gender, and sexual orientation preferences (men, women, everyone). It ensures the user is 18+ (validating birth date) and formats the data correctly for Tinder.  
- **Interests & Preferences**: Sets up additional profile details automatically, including **Interests** (hobbies like Travel, Movies, Reading), **Relationship Intent** (e.g. long-term), **Education Level**, and **Zodiac Sign**. These details make each profile look complete without manual input.  
- **Profile Photo Uploads**: Automatically uploads profile pictures to the new account. The script scans a `photos/` directory for images (JPEG/PNG), validates them, and uploads up to Tinder’s max of 9 photos per profile. It includes checks on image type and size, and provides feedback during upload (with retries for reliability).  
- **Proxy Support**: Supports HTTP and SOCKS5 proxies for account creation. You can route traffic through a proxy to manage IP addresses for each account (useful for privacy or avoiding IP rate limits). The script will test the proxy connection and show the external IP being used for Tinder’s API.  
- **Location Auto-Detection**: After account creation, the tool can automatically set the profile’s location based on the proxy’s IP address. It fetches approximate latitude/longitude from the IP and updates the Tinder profile location, emulating the Tinder app’s geolocation features.  
- **Robust Error Handling**: Built with error handling and retry logic for network calls. If an API call fails or returns an error (like a temporary network issue or a 401 Unauthorized), the script will retry and even refresh the authentication token if needed. It also attempts to handle captcha or challenge prompts from Tinder – if a challenge is encountered, it will try to solve it before proceeding.  
- **Session & Credential Saving**: After successful creation, the script saves the new account’s details. It outputs a summary including the Tinder user ID and the IP used. A session file (`tinder_session_<userID>.json`) is saved containing authentication tokens and device info for that account. It also logs the credentials in `tinder_credentials.json` for easy reference.

## Installation Guide
Follow these steps to set up the Bulk Tinder Profile Creator on your system:

1. **Clone the Repository**:  
   ```bash
   git clone https://github.com/riyadmondol2006/Bulk-Tinder-Profile-Creator.git
   cd Bulk-Tinder-Profile-Creator
   ```

2. **Install Python**:  
   Ensure you have **Python 3** installed. Verify by running:
   ```bash
   python --version
   ```
   If not installed, download it from the [official Python website](https://www.python.org/) or use your package manager.

3. **Install Dependencies**:  
   Install the required Python libraries. If a `requirements.txt` file is provided, run:
   ```bash
   pip install -r requirements.txt
   ```
   Otherwise, install the major libraries individually:
   ```bash
   pip install curl-cffi blackboxprotobuf cryptography
   ```

4. **Prepare Profile Photos**:  
   Create a folder named `photos` in the project directory and add the images you want to use for Tinder profile pictures. Tinder requires at least 2 photos for a new profile, so make sure to include 2 or more `.jpg` or `.png` images.

5. **Phone Number Setup**:  
   Have a valid phone number ready that can receive SMS. This number will be used to receive the OTP for Tinder’s phone verification during the account creation process.

## Usage Guide
Once the installation is complete, follow these steps to run the script:

- **Run the Script**:  
   Open a terminal in the project directory and run:
   ```bash
   python run.py
   ```

- **Proxy Selection**:  
   The script will prompt you to choose a proxy:
   - **1**: HTTP Proxy  
   - **2**: SOCKS5 Proxy  
   - **3**: No Proxy  
   Enter the appropriate number to configure proxy usage. If you choose a proxy, you will need to provide the proxy address in the specified format.

- **Enter Profile Details**:  
   You will be prompted to enter:
   - **Name**
   - **Date of Birth**
   - **Gender**
   - **Sexual Preference**
   - **Email Address**

- **Phone Verification (OTP)**:  
   Input your phone number and enter the OTP when received.

- **Onboarding & Profile Setup**:  
   The script configures the profile, interests, and preferences.

- **Photo Upload**:  
   Scans the `photos/` folder and uploads up to 9 images.

- **Finalize Account**:  
   Completes the registration and saves session details.

## Contact Information
For inquiries, support, or project quotes:

- **YouTube**: [Reversesio](https://www.youtube.com/@reversesio)
- **Blog**: [reversesio.com](http://reversesio.com/)
- **Simple Project Quotes**: [reversesio.shop](http://reversesio.shop/)
- **Telegram**: [@riyadmondol2006](https://t.me/riyadmondol2006)
- **Email**: [riyadmondol2006@gmail.com](mailto:riyadmondol2006@gmail.com)

---
*Star the repository on GitHub if you find this project useful!*

