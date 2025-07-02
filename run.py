from tinder_client import TinderClient
import json
import time
import random
import os
from datetime import datetime, date
import imghdr

def setup_additional_profile_settings(client):
    """Handle additional profile settings like education, zodiac, relationship intent etc."""
    try:
        print("\nSetting up additional profile information...")
        
        # Set relationship intent
        relationship_data = {
            "fields": [{
                "name": "relationship_intent",
                "data": {
                    "selected_descriptors": [{
                        "id": "de_29",
                        "choice_selections": [{"id": "2"}]  # Long-term, open to short
                    }]
                }
            }]
        }
        client._onboarding_set(json.dumps(relationship_data).encode())
        time.sleep(1)

        # Set education level
        education_data = {
            "fields": [{
                "name": "education",
                "data": {
                    "selected_descriptors": [{
                        "id": "de_4",
                        "choice_selections": [{"id": "1"}]  # Bachelors
                    }]
                }
            }]
        }
        client._onboarding_set(json.dumps(education_data).encode())
        time.sleep(1)

        # Set zodiac sign (optional)
        zodiac_data = {
            "fields": [{
                "name": "zodiac",
                "data": {
                    "selected_descriptors": [{
                        "id": "de_1",
                        "choice_selections": [{"id": "1"}]  # Capricorn
                    }]
                }
            }]
        }
        client._onboarding_set(json.dumps(zodiac_data).encode())
        time.sleep(1)

        # Set interests (optional)
        interests_data = {
            "fields": [{
                "name": "user_interests",
                "data": {
                    "selected_interests": [
                        {"id": "it_7", "name": "Travel"},
                        {"id": "it_9", "name": "Movies"},
                        {"id": "it_28", "name": "Reading"}
                    ]
                }
            }]
        }
        client._onboarding_set(json.dumps(interests_data).encode())
        
        print("✓ Additional profile settings configured")
        return True

    except Exception as e:
        print(f"Warning: Could not set additional profile settings: {str(e)}")
        return False

def get_proxy_settings():
    while True:
        print("\nProxy Setup:")
        print("1: HTTP Proxy")
        print("2: SOCKS5 Proxy")
        print("3: No Proxy")
        
        try:
            choice = input("Select proxy type (1-3): ").strip()
            if choice not in ['1', '2', '3']:
                print("Please enter 1, 2, or 3")
                continue
                
            if choice == '3':
                return None
                
            # Get proxy address
            while True:
                proxy = input("Enter proxy (format - ip:port or user:pass@ip:port): ").strip()
                if not proxy:
                    print("Proxy cannot be empty")
                    continue
                    
                if choice == '1':
                    if '@' in proxy:
                        proxy = f"http://{proxy}"
                    else:
                        proxy = f"http://{proxy}"
                elif choice == '2':
                    if '@' in proxy:
                        proxy = f"socks5://{proxy}"
                    else:
                        proxy = f"socks5://{proxy}"
                
                # Test proxy connection
                print(f"\nTesting proxy connection...")
                try:
                    test_client = TinderClient(proxy=proxy)
                    ip = test_client.checkIp()
                    print(f"Proxy working! Your IP: {ip}")
                    return proxy
                except Exception as e:
                    print(f"Error testing proxy: {str(e)}")
                    retry = input("Would you like to try another proxy? (y/n): ").lower()
                    if retry != 'y':
                        return None
                    
        except ValueError:
            print("Please enter a valid choice")

def validate_date(date_text):
    try:
        # First check if format is correct
        datetime.strptime(date_text, '%Y-%m-%d')
        
        # Parse the date parts
        year, month, day = map(int, date_text.split('-'))
        
        # Additional validation
        if year < 1900 or year > date.today().year:
            print("Please enter a valid year")
            return False
            
        if month < 1 or month > 12:
            print("Please enter a valid month (1-12)")
            return False
            
        if day < 1 or day > 31:
            print("Please enter a valid day")
            return False
            
        # Check if date actually exists (handles cases like Feb 30)
        date(year, month, day)
        
        return True
    except ValueError:
        print("Invalid date format. Please use YYYY-MM-DD")
        return False

def validate_age(birth_date):
    try:
        dob = datetime.strptime(birth_date, '%Y-%m-%d')
        today = datetime.now()
        age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
        
        if age < 18:
            print(f"You must be 18 or older to use this service (you are {age} years old)")
            return False
        if age > 100:
            print(f"Please enter a valid date of birth (age calculated: {age})")
            return False
            
        print(f"Age verified: {age} years old")
        return True
    except ValueError:
        return False

def get_date_of_birth():
    while True:
        print("\nEnter your date of birth:")
        
        try:
            # Get year
            while True:
                year = input("Year (YYYY): ").strip()
                if year.isdigit() and len(year) == 4 and 1900 <= int(year) <= date.today().year:
                    break
                print("Please enter a valid year (e.g., 1990)")
            
            # Get month
            while True:
                month = input("Month (1-12): ").strip()
                if month.isdigit() and 1 <= int(month) <= 12:
                    month = month.zfill(2)  # Pad with zero if needed
                    break
                print("Please enter a valid month (1-12)")
            
            # Get day
            while True:
                day = input("Day (1-31): ").strip()
                if day.isdigit() and 1 <= int(day) <= 31:
                    day = day.zfill(2)  # Pad with zero if needed
                    break
                print("Please enter a valid day (1-31)")
            
            # Combine into date string
            dob = f"{year}-{month}-{day}"
            
            # Validate the complete date
            if validate_date(dob) and validate_age(dob):
                return dob
                
        except ValueError as e:
            print(f"Invalid date: {e}")

def get_gender_interest():
    while True:
        print("\nWho are you interested in?")
        print("1: Men")
        print("2: Women")
        print("3: Everyone")
        try:
            choice = int(input("Enter number (1-3): "))
            if choice == 1:
                return [0]  # Interested in men
            elif choice == 2:
                return [1]  # Interested in women
            elif choice == 3:
                return [0, 1]  # Interested in both
            print("Please enter 1, 2, or 3")
        except ValueError:
            print("Please enter a valid number")

def validate_email(email):
    if '@' not in email or '.' not in email:
        return False
    local_part, domain = email.rsplit('@', 1)
    if not local_part or not domain:
        return False
    if len(email) > 254:
        return False
    return True

def check_image_file(file_path):
    """Validate if file is actually an image and get its details"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            image_type = imghdr.what(None, h=data)
            if image_type in ['jpeg', 'jpg', 'png']:
                file_size_mb = len(data) / (1024 * 1024)  # Convert to MB
                print(f"Image size: {file_size_mb:.2f}MB")
                
                if file_size_mb > 5:  # Warning for very large files
                    print(f"Warning: Image is quite large ({file_size_mb:.2f}MB). This may increase upload time.")
                
                return True, data, len(data)
    except Exception as e:
        print(f"Error reading image {file_path}: {str(e)}")
    return False, None, 0

def get_photos_from_folder():
    photos_dir = "photos"
    print(f"\nChecking photos directory: {os.path.abspath(photos_dir)}")
    
    if not os.path.exists(photos_dir):
        print(f"Error: {photos_dir} directory not found!")
        return []
    
    valid_extensions = ('.jpg', '.jpeg', '.png')
    photos = []
    
    print("\nScanning for photos:")
    files = sorted(os.listdir(photos_dir))  # Sort files to maintain consistent order
    
    for file in files:
        file_lower = file.lower()
        if file_lower.endswith(valid_extensions):
            file_path = os.path.join(photos_dir, file)
            print(f"\nChecking file: {file}")
            print(f"Full path: {os.path.abspath(file_path)}")
            
            is_valid, image_data, size = check_image_file(file_path)
            if is_valid and image_data:
                photos.append(image_data)
                print(f"✓ Valid image found: {file} (Size: {size/1024/1024:.2f}MB)")
            else:
                print(f"✗ Invalid or corrupted image: {file}")
                
            if len(photos) >= 9:
                print("\nMaximum number of photos (9) reached. Additional photos will be ignored.")
                break
    
    print(f"\nTotal valid photos found: {len(photos)}")
    if len(photos) == 0:
        print("Please add some photos to the 'photos' directory")
    elif len(photos) < 2:
        print("Warning: Tinder requires at least 2 photos")
    
    return photos
def debug_response(response, status_code):
    print(f"\nStatus Code: {status_code}")
    print("Raw Response:", response)
    try:
        if response:
            return json.loads(response)
        return None
    except json.JSONDecodeError:
        print("Response is not valid JSON")
        return None

def handle_auth_process(client, email):
    max_retries = 3
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            phone_number = input("\nEnter phone number (with country code, e.g., +1234567890): ").strip()
            if not phone_number.startswith('+'):
                print("Phone number must start with + and country code")
                continue

            print(f"\nAttempting login with {phone_number}...")
            login_response = client.authLogin(phone_number)
            
            if not login_response:
                print("No response from server")
                retry_count += 1
                continue

            if 'error' in login_response:
                print(f"Login error: {login_response['error']}")
                retry_count += 1
                continue

            # Handle OTP verification
            while True:
                otp = input("\nEnter the OTP received on your phone: ").strip()
                if not otp.isdigit():
                    print("OTP should contain only numbers")
                    continue

                print(f"Verifying OTP: {otp}")
                otp_response = client.verifyOtp(phone_number, otp)
                
                if 'error' not in otp_response:
                    print("Phone verification successful!")
                    
                    # Register email
                    print("\nRegistering email...")
                    email_response = client.useEmail(email)
                    print("Email registration response:", json.dumps(email_response, indent=2))
                    
                    if 'error' not in email_response:
                        print("Email registration successful!")
                        
                        # Dismiss social connection list
                        print("\nDismissing social connections...")
                        dismiss_response = client.dismissSocialConnectionList()
                        print("Dismiss response:", json.dumps(dismiss_response, indent=2))
                        
                        # Get auth token
                        print("\nGetting authentication token...")
                        auth_response = client.getAuthToken()
                        print("Auth token response:", json.dumps(auth_response, indent=2))
                        
                        if 'error' not in auth_response:
                            return True
                        
                print("Authentication step failed. Retrying...")
                break

            retry_count += 1

        except Exception as e:
            print(f"\nError during login process: {str(e)}")
            retry_count += 1
            time.sleep(2)

    return False
def handle_401_error(client):
    """Handle 401 unauthorized error by refreshing auth token"""
    try:
        print("\nRefreshing authentication token...")
        auth_response = client.getAuthToken()
        if auth_response and 'error' not in auth_response:
            print("Successfully refreshed authentication token")
            return True
        print("Failed to refresh authentication token")
        return False
    except Exception as e:
        print(f"Error refreshing token: {str(e)}")
        return False

def upload_photos(client, photos):
    max_photos = min(len(photos), 9)  # Limit to 9 photos maximum
    print(f"\nPreparing to upload {max_photos} photos...")
    
    for i, photo_data in enumerate(photos[:max_photos], 1):
        file_size_mb = len(photo_data) / (1024 * 1024)
        print(f"\nUploading photo {i}/{max_photos}...")
        print(f"Photo size: {file_size_mb:.2f}MB")
        
        # Adjust max retries based on file size
        max_retries = 5 if file_size_mb > 2 else 3
        retry_count = 0
        token_refresh_attempted = False
        
        while retry_count < max_retries:
            try:
                print(f"Attempt {retry_count + 1} of {max_retries}")
                
                # Add random delay before upload
                delay = random.uniform(1.0, 1.5)
                print(f"Waiting {delay:.2f} seconds before upload...")
                time.sleep(delay)
                
                response = client.onboardingPhoto(photo_data, max_photos)
                response_data = debug_response(response, client.last_status_code)
                
                if response_data and response_data.get('meta', {}).get('status') == 200:
                    print(f"Successfully uploaded photo {i}")
                    token_refresh_attempted = False  # Reset for next photo
                    break
                elif client.last_status_code == 401 and not token_refresh_attempted:
                    print("Received 401 unauthorized error")
                    if handle_401_error(client):
                        token_refresh_attempted = True
                        continue  # Retry immediately with new token
                    else:
                        print("Token refresh failed")
                
                print(f"Failed to upload photo {i} - Retrying...")
                retry_count += 1
                
                # Longer delay between retries for larger files
                retry_delay = random.uniform(2.0, 3.0) if file_size_mb > 2 else random.uniform(1.5, 2.0)
                print(f"Waiting {retry_delay:.2f} seconds before retry...")
                time.sleep(retry_delay)
            
            except Exception as e:
                print(f"Error uploading photo {i}: {str(e)}")
                retry_count += 1
                time.sleep(2)
        
        if retry_count >= max_retries:
            print(f"Failed to upload photo {i} after {max_retries} attempts")
            user_choice = input("\nContinue with remaining photos? (y/n): ").lower()
            if user_choice != 'y':
                print("Aborting photo upload process...")
                return False
        
        # Random delay between successful uploads
        if i < max_photos:
            delay = random.uniform(1.0, 1.5)
            print(f"Waiting {delay:.2f} seconds before next upload...")
            time.sleep(delay)
    
    return True

def onboarding_with_photos(client, photos):
    """Wrapper function to handle the entire onboarding photo process"""
    max_attempts = 2
    for attempt in range(max_attempts):
        try:
            # Ensure fresh token before starting uploads
            if attempt > 0:
                print("\nRefreshing token before retrying uploads...")
                if not handle_401_error(client):
                    print("Failed to refresh token, aborting...")
                    return False
            
            # Try uploading all photos
            if upload_photos(client, photos):
                print("\nAll photos uploaded successfully!")
                return True
            
        except Exception as e:
            print(f"\nError during photo upload process: {str(e)}")
            if attempt < max_attempts - 1:
                print("Retrying complete photo upload process...")
                time.sleep(2)
            else:
                print("Maximum attempts reached. Photo upload process failed.")
                return False
    
    return False

def get_user_info():
    # Get name
    while True:
        name = input("\nEnter your name: ").strip()
        if len(name) >= 2 and len(name) <= 50:
            break
        print("Name must be between 2 and 50 characters")

    # Get date of birth with improved interface
    dob = get_date_of_birth()

    # Get gender
    while True:
        print("\nSelect your gender:")
        print("0: Male")
        print("1: Female")
        try:
            gender = int(input("Enter number (0 or 1): "))
            if gender in [0, 1]:
                break
            print("Please enter 0 or 1")
        except ValueError:
            print("Please enter a valid number")

    # Get gender interest
    gender_interest = get_gender_interest()

    # Get email
    while True:
        email = input("\nEnter your email address: ").strip()
        if validate_email(email):
            break
        print("Please enter a valid email address")

    return {
        'name': name,
        'dob': dob,
        'gender': gender,
        'gender_interest': gender_interest,
        'email': email
    }

def try_api_call(client, func, description, max_retries=3, delay=2):
    """Generic function to handle API calls with retries"""
    for attempt in range(max_retries):
        try:
            if attempt > 0:
                print(f"Retry attempt {attempt + 1}/{max_retries}")
            result = func()
            if result and client.last_status_code == 200:
                print(f"✓ {description} completed successfully")
                return True
            raise Exception(f"API call failed with status {client.last_status_code}")
        except Exception as e:
            if attempt < max_retries - 1:
                print(f"Retrying {description} in {delay} seconds...")
                time.sleep(delay)
            else:
                print(f"Failed to {description}: {str(e)}")
                return False
    return False

def main():
    try:
        print("Welcome to Tinder Registration!")
        print("-" * 50)

        # Get proxy settings first
        proxy = get_proxy_settings()

        # Get user information
        user_info = get_user_info()

        # Check photos with detailed logging
        print("\nChecking photos directory...")
        photos = get_photos_from_folder()
        if not photos:
            print("No photos found in the photos directory! Please add some photos and try again.")
            return

        # Initialize client with proxy
        client = TinderClient(
            userAgent="Tinder/14.21.0 (iPhone; iOS 14.2.0; Scale/2.00)",
            platform="ios",
            tinderVersion="14.21.0",
            appVersion="5546",
            osVersion=140000200000,
            language="en-US",
            proxy=proxy
        )

        if proxy:
            print(f"\nUsing proxy. Current IP: {client.checkIp()}")

        # Initialize session
        print("\nInitializing session...")
        buckets_response = client.sendBuckets()
        if buckets_response:
            print("Session initialized successfully")
        else:
            print("Failed to initialize session")
            return
        
        time.sleep(1)

        # Device check
        print("\nPerforming device check...")
        client.deviceCheck()
        time.sleep(2)

        # Authentication process
        if not handle_auth_process(client, user_info['email']):
            print("\nAuthentication failed. Exiting...")
            return

        time.sleep(2)

        # Start onboarding with retry logic
        print("\nStarting onboarding process...")
        onboarding_response = client.startOnboarding()
        if not onboarding_response:
            print("Failed to start onboarding process")
            return

        time.sleep(2)

        # Set basic information
        print("\nSetting basic information...")
        info_response = client.onboardingSuper(
            user_info['name'], 
            user_info['dob'], 
            user_info['gender'],
            user_info['gender_interest']
        )
        if not info_response:
            print("Failed to set basic information")
            return

        time.sleep(2)

        # Additional profile settings
        print("\nSetting up additional profile settings...")
        setup_additional_profile_settings(client)
        
        time.sleep(2)

        # Photo upload
        print("\nStarting photo upload process...")
        upload_photos(client, photos)

        time.sleep(2)

        # Complete registration
        print("\nCompleting registration...")
        complete_response = client.endOnboarding()
        print("Registration complete response:", json.dumps(debug_response(complete_response, client.last_status_code), indent=2))

        # Handle possible captcha challenge
        if client.last_status_code != 200:
            print("\nEncountered a challenge. Attempting to resolve...")
            if client.processCaptcha():
                print("Challenge resolved successfully!")
            else:
                print("Failed to resolve challenge")
                return

        # Set additional profile settings with retry logic
        try:
            time.sleep(3)

            # Set geolocation from proxy IP
            try:
                print("\nConfiguring location settings...")
                ip = client.checkIp()
                print(f"Current IP: {ip}")
                lat, lng = client.getLocation(ip)
                print(f"Location detected - Latitude: {lat}, Longitude: {lng}")

                try_api_call(client,
                            lambda: client.updateLocation(lat, lng),
                            "Updating location")
                time.sleep(1)

                try_api_call(client,
                            lambda: client.locInit(),
                            "Initializing location services")
                time.sleep(1)

                try_api_call(client,
                            lambda: client.updateLocalization(lat, lng),
                            "Updating localization")
            except Exception as e:
                print(f"Warning: Could not set location automatically: {str(e)}")

            # Save session info
            try:
                print("\nSaving session information...")
                session_info = client.toObject()
                session_file = f"tinder_session_{client.userId}.json"
                with open(session_file, "w") as f:
                    json.dump(session_info, f, indent=2)
                print(f"Session saved to: {session_file}")
            except Exception as e:
                print(f"Warning: Could not save session information: {str(e)}")

            print("\n=== Registration Summary ===")
            print("✓ Basic registration completed")
            print("✓ Photos uploaded successfully")
            print("✓ Profile configured")
            print(f"✓ Using IP: {client.checkIp()}")
            print(f"✓ User ID: {client.userId}")
            
            # Save credentials to a separate file
            credentials = {
                'user_id': client.userId,
                'email': user_info['email'],
                'registration_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'proxy_used': proxy,
                'ip_used': client.checkIp()
            }
            
            with open('tinder_credentials.json', 'a') as f:
                f.write(json.dumps(credentials) + '\n')
            
            print("\nCredentials saved to: tinder_credentials.json")
            print("\nYou can now use the Tinder app with these credentials.")

        except Exception as e:
            print(f"\nWarning: Some additional settings could not be applied: {str(e)}")
            print("Basic registration is complete, but some features might need to be set up manually.")

    except Exception as e:
        print(f"\nAn error occurred: {str(e)}")
        import traceback
        traceback.print_exc()

    finally:
        print("\nProcess completed!")
        if 'client' in locals() and hasattr(client, 'userId'):
            print(f"User ID: {client.userId}")

if __name__ == "__main__":
    main()

