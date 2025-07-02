# Bulk Tinder Profile Creator with DaisySMS Integration

An automated Tinder profile creation tool that uses DaisySMS API for phone number verification, eliminating the need for manual phone number input and SMS verification.

## 🚀 Features

- **Automated Phone Verification**: Uses DaisySMS API to automatically rent phone numbers and receive SMS verification codes
- **Bulk Profile Creation**: Create multiple Tinder profiles efficiently
- **Photo Upload**: Automatically uploads photos from the `photos/` directory
- **Proxy Support**: HTTP and SOCKS5 proxy support for different IP addresses
- **Error Handling**: Comprehensive error handling with retry mechanisms
- **Profile Customization**: Set up complete profiles with interests, education, relationship intent, etc.

## 📋 Prerequisites

### 1. DaisySMS Account Setup
1. Visit [DaisySMS.com](https://daisysms.com/)
2. Create an account
3. Add funds to your balance (recommended: $10+ for multiple profiles)
4. Get your API key from the API section

### 2. System Requirements
- Python 3.8+
- All dependencies from `requirements.txt`
- Photos for profile (place in `photos/` directory)

## 🛠 Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd Bulk-Tinder-Profile-Creator
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Add your photos:**
   - Place your photos in the `photos/` directory
   - Supported formats: JPG, JPEG, PNG
   - Minimum 2 photos required
   - Maximum 9 photos supported

## 🚀 Quick Start

### Step 1: Test DaisySMS Setup
Before running the full registration, test your DaisySMS API setup:

   ```bash
python test_daisysms.py
```

This will:
- Validate your API key
- Check your account balance
- Test number rental for Tinder service
- Cancel the rental to avoid charges

### Step 2: Run Profile Creation
   ```bash
   python run.py
   ```

The script will guide you through:
1. **DaisySMS Configuration**: Enter your API key
2. **Proxy Setup**: Choose HTTP, SOCKS5, or no proxy
3. **Profile Information**: Name, date of birth, gender, interests, email
4. **Photo Upload**: Automatic upload from `photos/` directory
5. **Phone Verification**: Automated using DaisySMS
6. **Profile Completion**: Additional settings and finalization

## 📞 DaisySMS Integration Details

### Service Code
- **Tinder Service Code**: `oi`
- **Max Price**: $3.00 per number (configurable)
- **Timeout**: 3 minutes for SMS reception

### API Operations
1. **Rent Number**: Automatically rents a phone number for Tinder verification
2. **SMS Reception**: Polls for SMS verification code every 3 seconds
3. **Code Extraction**: Extracts verification code from received SMS
4. **Cleanup**: Marks rental as done to free up slots

### Error Handling
- **No Numbers Available**: Retries with delays
- **Price Exceeded**: Configurable max price limit
- **SMS Timeout**: 180-second timeout with automatic retry
- **Network Errors**: Automatic retry with exponential backoff

## 🔧 Configuration Options

### DaisySMS Settings
```python
# In run.py, you can modify these parameters:
rental_id, phone_number = daisysms_client.rent_number(
    service='oi',           # Tinder service code
    max_price=3.0,          # Maximum price in USD
    max_retries=3           # Retry attempts
)

otp_code = daisysms_client.get_sms_code(
    rental_id,
    timeout=180,            # SMS timeout in seconds
    poll_interval=3         # Polling interval in seconds
)
```

### Proxy Configuration
- **HTTP Proxy**: `http://username:password@ip:port`
- **SOCKS5 Proxy**: `socks5://username:password@ip:port`
- **Authentication**: Supports username/password authentication

## 📁 File Structure

```
Bulk-Tinder-Profile-Creator/
├── run.py                 # Main registration script
├── test_daisysms.py      # DaisySMS API test script
├── tinder_client.py      # Tinder API client
├── requirements.txt      # Python dependencies
├── photos/               # Directory for profile photos
│   ├── photo1.jpg
│   ├── photo2.png
│   └── ...
├── proto/                # Protocol buffer definitions
└── blackboxprotobuf/     # Protocol buffer handling
```

## 🔍 Troubleshooting

### Common DaisySMS Issues

1. **"NO_NUMBERS" Error**
   - No Tinder numbers available at the moment
   - Try again in 5-10 minutes
   - Peak hours may have limited availability

2. **"MAX_PRICE_EXCEEDED" Error**
   - Current price is higher than your max_price setting
   - Increase max_price in the script or wait for prices to decrease

3. **"NO_MONEY" Error**
   - Add more funds to your DaisySMS account
   - Each Tinder verification typically costs $0.50-$2.00

4. **"TOO_MANY_ACTIVE_RENTALS" Error**
   - Complete or cancel existing rentals
   - Maximum is typically 20 active rentals

### SMS Reception Issues

1. **SMS Timeout**
   - Sometimes SMS delivery can be delayed
   - The script automatically retries with a new number
   - Try during off-peak hours for better reliability

2. **Invalid Verification Code**
   - Rare issue with SMS parsing
   - Script will automatically retry with a new number

### Profile Creation Issues

1. **Photo Upload Failures**
   - Check image file format (JPG, PNG supported)
   - Ensure images are not corrupted
   - Verify image file sizes (< 5MB recommended)

2. **Captcha Challenges**
   - Script includes captcha handling
   - Manual intervention may be required for complex captchas

## 💡 Tips for Success

1. **Account Balance**: Keep sufficient balance ($10+ recommended)
2. **Photo Quality**: Use high-quality, clear photos
3. **Timing**: Run during off-peak hours for better number availability
4. **Proxy Rotation**: Use different proxies for each profile
5. **Rate Limiting**: Don't create too many profiles rapidly

## 🛡 Security Considerations

- **API Key Protection**: Never share your DaisySMS API key
- **Proxy Safety**: Use reputable proxy services
- **Data Privacy**: Be cautious with personal information
- **Rate Limiting**: Respect service rate limits to avoid blocks

## 📊 Cost Breakdown

Typical costs per profile creation:
- **Phone Verification**: $0.50 - $2.00
- **Proxy (optional)**: $0.01 - $0.10
- **Total per profile**: $0.50 - $2.10

## 🤝 Support

For issues related to:
- **DaisySMS API**: Contact [DaisySMS Support](mailto:support@daisysms.com)
- **Script Issues**: Check troubleshooting section above
- **Tinder API Changes**: Monitor for updates

## ⚖️ Disclaimer

This tool is for educational and testing purposes. Users are responsible for:
- Complying with Tinder's Terms of Service
- Following local laws and regulations
- Using the tool ethically and responsibly

## 📝 Changelog

### v2.0.0 - DaisySMS Integration
- Added automated phone number verification
- Integrated DaisySMS API client
- Enhanced error handling and retry mechanisms
- Added test script for API validation
- Improved user experience with automated flow

### v1.0.0 - Initial Release
- Basic Tinder profile creation
- Manual phone verification
- Photo upload functionality
- Proxy support

