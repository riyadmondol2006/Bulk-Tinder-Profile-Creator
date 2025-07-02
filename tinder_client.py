import random
import base64
import uuid
import os
import json
import time
import re
import urllib.parse
import asyncio
from logging import Logger
from datetime import datetime, timezone
from curl_cffi.requests import AsyncSession, WebSocket, Session
from threading import Thread
from dataclasses import dataclass
from typing import Optional, Tuple, Dict, List

import blackboxprotobuf
import blackboxprotobuf.lib.protofile as protofile
from blackboxprotobuf.lib.config import Config

# Additional imports for device token generation
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import struct

# Constants for device token generation
pub = b''.join([
    b'\x04\x50\xD9\x34\xFA\x67\xBC\xF6\xF2\xDF\xBF\x96\x62\x9E\x0A\x72',
    b'\x38\xE9\x20\x5D\x75\xF2\x8C\xFC\xD8\x4F\x35\xA6\x59\x2B\xBE\x05',
    b'\x8A\x9C\x0F\x8E\xDB\xCA\x2A\xCB\x67\xEF\xB7\x74\x97\x1C\xA4\x5F',
    b'\x7D\x85\x6A\x69\x4F\xB1\xB9\xC4\x0B\x94\xFB\x2E\x7A\x5A\x94\x98',
    b'\xB0'])

keys = [
    (
        bytes.fromhex('442b139ff63f7c4bcbd2c0cd579bf1eea19e892472a8b7f9a08e0e2fc98a55ca'),
        bytes.fromhex('f3315c156e2d58725d0aafd0'),
        pub,
        b''.join([
            b'\x04\xD6\x65\x09\xAE\x95\x8E\x95\x26\x18\x48\x8A\xA4\xBC\x3E\xA8',
            b'\x60\x44\xA2\xA3\xBF\xA0\x01\xEC\x97\x9B\x29\xEE\xA4\xB4\x64\x5E',
            b'\x84\xFE\x25\x08\x92\x6F\x04\x53\xCD\xC2\xAC\x4A\xF5\xA3\x22\x1D',
            b'\x68\xC7\x88\x79\x56\x80\x8E\xE3\xB5\x89\x02\xB7\xE2\x62\x74\xD6',
            b'\xD7'])
    )
]

# Utility functions for device token generation
def rand_key():
    return keys[0]

def get_device_cer():
    return bytes.fromhex('2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d494944556a434341766567417749424167494741592f374c7634444d416f4743437147534d343942414d434d464d784a7a416c42674e5642414d4d486b4a680d0a63326c6a494546306447567a64474630615739754946567a5a5849675533566949454e424d5445544d424547413155454367774b51584277624755675357356a0d0a4c6a45544d424547413155454341774b5132467361575a76636d357059544165467730794e4441324d4467774e4441344d7a4a61467730794e54417a4d5449770d0a4f5455354d7a4a614d4947524d556b775277594456515144444541784d6a41784f4449315a6d45354d445a6a4e3246684f4751794f5449324e574978596a566c0d0a5957526b5a5464685a4455794e7a4531596d55324f47526b597a49794e6a52694d4467304d474e684e325a6a4e7a68684d526f77474159445651514c444246430d0a515545675132567964476c6d61574e6864476c76626a45544d424547413155454367774b51584277624755675357356a4c6a45544d424547413155454341774b0d0a5132467361575a76636d35705954425a4d424d4742797147534d34394167454743437147534d34394177454841304941424f752f585856546d32774c327042640d0a6f31707434717464694b596b3143734b556b546a34314654387937746d5a6b6a58697176677451487a53697550385a47304c4168784d734a4d6a614f482b74500d0a2f354738574f616a676746324d494942636a414d42674e5648524d4241663845416a41414d41344741315564447745422f7751454177494538444343415641470d0a43537147534962335932514b4151534341554545676745394d5949424f662b456b72326b5241737743525945516b39535241494244502b456d714753554130770d0a437859455130684a55414944414941512f3453716a5a4a45455441504667524651306c4541676359654f496b2b514d6d2f34615474634a6a477a415a466752690d0a6257466a4242466a4d44706b4d446f784d6a70684d44706b4d7a6f774e762b477937584b61526b77467859456157316c615151504d7a55314d7a49344d4467330d0a4e5459344e6a6b7a2f34656279647874466a41554667527a636d3574424178474d546455526a46574d5568484e30662f68367552306d51794d4441574248566b0d0a615751454b4459334e3256684d4463344d6d4e684d7a557a593255304d6d4a6b4d325532597a6c6b4e7a526c4d5467344f47466b595451794e546a2f683775310d0a776d4d624d426b574248647459574d4545574d774f6d51774f6a45794f6d45774f6d51794f6d45302f3465626c644a6b4f6a41344667527a5a576c6b424441770d0a4e4451794d6a45304d7a42434d3055344d4441784e6a4d774f5441784f4467354d546b7a4f546b774d454e444f544977517a46454d545a434d6a5178525545770d0a436759494b6f5a497a6a304541774944535141775267496841507a367635514634745439446472772b38307674776938476e6c2f4f682f616c62436c385977490d0a56724d534169454137676859526a38556c784f5471694c7a4658364f79635037486c6b644d392f3664542f3976596a654148453d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d494943497a4343416169674177494241674949654e6a684739746e44476777436759494b6f5a497a6a304541774977557a456e4d43554741315545417777650d0a516d467a61574d67515852305a584e30595852706232346756584e6c636942536232393049454e424d524d77455159445651514b44417042634842735a53424a0d0a626d4d754d524d77455159445651514944417044595778705a6d3979626d6c684d423458445445334d4451794d4441774e4449774d466f5844544d794d444d790d0a4d6a41774d4441774d466f77557a456e4d4355474131554541777765516d467a61574d67515852305a584e30595852706232346756584e6c63694254645749670d0a513045784d524d77455159445651514b44417042634842735a53424a626d4d754d524d77455159445651514944417044595778705a6d3979626d6c684d466b770d0a457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741456f535a2f31743965424145567035613850725861636d624762387a4e433158330d0a53744c4939594f365930434c37626c486d53476d6a475754774434512b69304a324259332b6250485447527941396a4742334d5362614e6d4d475177456759440d0a565230544151482f42416777426745422f7749424144416642674e5648534d45474441576742534435614d686e724230772f6c686b50325854694d516471536a0d0a386a416442674e564851344546675155356d57663144594c545855645139786d4f482f7571654e534438307744675944565230504151482f42415144416745470d0a4d416f4743437147534d343942414d4341326b414d4759434d5143334d3336304c4c744a5336305a39713376566a4a784d674d63465131726f475455634b71760d0a572b34684a3443654a6a795358546771364945486e2f7957616234434d51436d354e6e4b36534f534b2b417157756d396c4c383757334536414131663254764a0d0a2f68676f6b2f33346a7239336e68533837744f514e64784453387a796971773d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d')

def aes_gcm_encrypt(key: bytes, iv: bytes, data: bytes):
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(data) + encryptor.finalize()

    return (ciphertext, encryptor.tag)

def aes_gcm_decrypt(key: bytes, iv: bytes, data: bytes, tag: bytes):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    plaintext = decryptor.update(data) + decryptor.finalize()

    return plaintext

def generateDeviceToken(appId: str):
    appId = appId.encode()
    KEY, IV, PUB, RAND = rand_key()
    device_cer = get_device_cer()
    now = time.time()

    rawDeviceID = RAND + struct.pack('<dii', now, len(device_cer), len(appId)) + device_cer + appId
    body, tag = aes_gcm_encrypt(KEY, IV, rawDeviceID)
    deviceID = b'\x02\x00\x00\x00' + tag + PUB + RAND + struct.pack('<i', len(body)) + body

    return base64.b64encode(deviceID).decode()

# Original code from the first document continues here
config = Config()
typedef_map = protofile.import_proto(config, input_filename='./proto/tinder.proto')
config.known_types = typedef_map

# Headers order: https://github.com/lexiforest/curl_cffi/issues/335
http_async_sesion = Session(
    verify=False,
    default_headers=False,
    impersonate="safari17_2_ios",
)

@dataclass
class DeviceProfile:
    device_model: str
    os_version: str
    build_id: str
    carrier: Optional[str] = None
    
    def encode(self) -> str:
        return base64.b64encode(self.device_model.encode()).decode()

class DeviceProfileManager:
    # Common iOS devices that support Tinder with full version numbers
    IOS_DEVICES: List[DeviceProfile] = [
        DeviceProfile("iPhone8,1", "14.2.0", "18B92", "AT&T"),  # iPhone 6s
        DeviceProfile("iPhone8,2", "14.2.0", "18B92", "T-Mobile"),  # iPhone 6s Plus
        DeviceProfile("iPhone9,1", "14.2.0", "18B92", "Verizon"),  # iPhone 7
        DeviceProfile("iPhone9,3", "14.2.0", "18B92", "Sprint"),  # iPhone 7
        DeviceProfile("iPhone9,2", "14.2.0", "18B92", "AT&T"),  # iPhone 7 Plus
        DeviceProfile("iPhone9,4", "14.2.0", "18B92", "T-Mobile"),  # iPhone 7 Plus
        DeviceProfile("iPhone10,1", "14.2.0", "18B92", "Verizon"),  # iPhone 8
        DeviceProfile("iPhone10,4", "14.2.0", "18B92", "Sprint"),  # iPhone 8
        DeviceProfile("iPhone10,2", "14.2.0", "18B92", "AT&T"),  # iPhone 8 Plus
        DeviceProfile("iPhone10,5", "14.2.0", "18B92", "T-Mobile"),  # iPhone 8 Plus
    ]

    # Common carriers and their codes
    CARRIERS: Dict[str, Tuple[int, int]] = {
        "AT&T": (310, 410),
        "T-Mobile": (310, 260),
        "Verizon": (311, 480),
        "Sprint": (310, 120),
        "": (0, 0)  # No carrier
    }

    @staticmethod
    def generate_device_id() -> str:
        """Generate a realistic iOS device ID."""
        return uuid.uuid4().hex[:16]  # iOS uses 16-byte device IDs

    @staticmethod
    def generate_install_id() -> str:
        """Generate an installation ID in UUID format."""
        return str(uuid.uuid4()).upper()

    @staticmethod
    def parse_ios_version(version_str: str) -> int:
        """Convert iOS version string to numeric format."""
        # Split version string and pad with zeros if needed
        parts = version_str.split('.')
        while len(parts) < 3:
            parts.append('0')
        major, minor, patch = map(int, parts)
        return (major * 10000000000) + (minor * 100000000) + (patch * 1000000)

    @classmethod
    def generate_profile(cls) -> Tuple[Dict[str, any], DeviceProfile]:
        """Generate a complete device profile with consistent information."""
        # Select random device profile
        device_profile = random.choice(cls.IOS_DEVICES)
        
        # Generate consistent IDs
        device_id = cls.generate_device_id()
        install_id = cls.generate_install_id()
        session_id = str(uuid.uuid4()).upper()
        
        # Get carrier codes
        mcc, mnc = cls.CARRIERS.get(device_profile.carrier or "", (0, 0))
        
        # Create user agent - note we use the first two parts of version for user agent
        display_version = '.'.join(device_profile.os_version.split('.')[:2])
        user_agent = (f"Tinder/14.21.0 ({device_profile.device_model}; "
                     f"iOS {display_version}; Scale/2.00)")
        
        # Create complete profile
        profile = {
            "userAgent": user_agent,
            "persistentDeviceId": device_id,
            "installId": install_id,
            "appSessionId": session_id,
            "encodedDeviceModel": device_profile.encode(),
            "encodedDeviceCarrier": (base64.b64encode(device_profile.carrier.encode()).decode() 
                                   if device_profile.carrier else ""),
            "mobileCountryCode": mcc,
            "mobileNetworkCode": mnc,
            "osVersion": cls.parse_ios_version(device_profile.os_version),
            "platform": "ios",
            "language": "en-US",
            "tinderVersion": "14.21.0",
            "appVersion": "5546"
        }
        
        return profile, device_profile

def generateAppsFlyerId() -> str:
    part1 = str(random.randint(0, int(1e13))).zfill(13)[:13]
    part2 = str(random.randint(0, int(1e16))).zfill(16) + str(random.randint(0, int(1e3))).zfill(3)
    return f"{part1}-{part2[:19]}"

def bytes2base64(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')

class TinderClient:
    def __init__(
            self,
            userAgent: str = None,
            proxy: str = None,
            persistentDeviceId: str = None,
            appSessionId: str = None,
            installId: str = None,
            encodedDeviceModel: str = None,
            encodedDeviceCarrier: str = None,
            mobileCountryCode: int = None,
            mobileNetworkCode: int = None,
            tinderVersion: str = None,
            appVersion: str = None,
            storeVariant: str = None,
            osVersion: int = None,
            platform: str = None,
            platformVariant: str = None,
            language: str = None,
            funnelSessionId: str = None,
            appsFlyerId: str = None,
            advertisingId: str = None,
            refreshToken: str = None,
            userId: str = None,
            onboardingToken: str = None,
            xAuthToken: str = None,
            userSessionId: str = None,
            appId: str = None,
            userSessionStartTime: int = 0
    ):
        # Generate device profile if minimal params aren't provided
        if not all([userAgent, persistentDeviceId, encodedDeviceModel, osVersion]):
            profile, device_profile = DeviceProfileManager.generate_profile()
            self.device_profile = device_profile
            
            # Apply generated profile settings
            userAgent = profile["userAgent"]
            persistentDeviceId = profile["persistentDeviceId"]
            installId = profile["installId"]
            encodedDeviceModel = profile["encodedDeviceModel"]
            encodedDeviceCarrier = profile["encodedDeviceCarrier"]
            mobileCountryCode = profile["mobileCountryCode"]
            mobileNetworkCode = profile["mobileNetworkCode"]
            osVersion = profile["osVersion"]
            platform = profile["platform"]
            language = profile["language"]
            tinderVersion = profile["tinderVersion"]
            appVersion = profile["appVersion"]
        
        app_boot_time = random.uniform(40, 50)
        if installId:
            self.first_boot = False
        else:
            self.first_boot = True
        
        self.appSessionId = appSessionId or str(uuid.uuid4()).upper()
        self.appSessionStartTime = time.time() - app_boot_time
        self.persistentDeviceId = persistentDeviceId
        self.installId = installId
        self.encodedDeviceModel = encodedDeviceModel
        self.encodedDeviceCarrier = encodedDeviceCarrier
        self.mobileCountryCode = mobileCountryCode
        self.mobileNetworkCode = mobileNetworkCode
        self.tinderVersion = tinderVersion or "14.21.0"
        self.appVersion = appVersion or "5546"
        self.storeVariant = storeVariant
        self.language = language or "en-US"
        self.platformVariant = platformVariant
        self.platform = platform or "ios"
        self.osVersion = osVersion
        self.userAgent = userAgent
        self.appsFlyerId = appsFlyerId or generateAppsFlyerId()
        self.advertisingId = advertisingId or str(uuid.uuid4())
        self.funnelSessionId = funnelSessionId or os.urandom(16).hex()
        self.onboardingToken = onboardingToken
        self.userId = userId
        self.refreshToken = refreshToken
        self.xAuthToken = xAuthToken

        if xAuthToken:
            self.userSessionId = userSessionId or str(uuid.uuid4()).upper()
            self.userSessionStartTime = time.time() - app_boot_time
        else:
            self.userSessionId = userSessionId
            self.userSessionStartTime = userSessionStartTime

        self.app_id = appId
        self.httpProxy = proxy
        self.app_seconds = 0
        self.user_seconds = 0
        self.last_status_code = 0
        self.onboardingPayload = []

        self.URL_ONBOARDING = 'https://api.gotinder.com/v2/onboarding/fields?requested=name&requested=birth_date&requested=gender&requested=custom_gender&requested=show_gender_on_profile&requested=photos&requested=schools&requested=consents&requested=videos_processing&requested=sexual_orientations&requested=show_same_orientation_first&requested=show_orientation_on_profile&requested=interested_in_gender&requested=user_interests&requested=distance_filter&requested=tinder_rules&requested=relationship_intent&requested=basics&requested=lifestyle'
        self.URL_ONBOARDING_PHOTO = self.URL_ONBOARDING.replace('/fields?', '/photo?', 1)
        self.URL_ONBOARDING_COMPLETE = self.URL_ONBOARDING.replace('/fields?', '/complete?', 1)
        self.URL_DEVICE_CHECK = 'https://api.gotinder.com/v2/device-check/ios'

    def rotate_device(self):
        """Rotate device profile while maintaining session data."""
        profile, device_profile = DeviceProfileManager.generate_profile()
        
        # Update device-specific attributes
        self.userAgent = profile["userAgent"]
        self.encodedDeviceModel = profile["encodedDeviceModel"]
        self.encodedDeviceCarrier = profile["encodedDeviceCarrier"]
        self.mobileCountryCode = profile["mobileCountryCode"]
        self.mobileNetworkCode = profile["mobileNetworkCode"]
        self.osVersion = profile["osVersion"]
        self.device_profile = device_profile
        
        return self

    @staticmethod
    def fromObject(o: dict) -> 'TinderClient':
        return TinderClient(**o)
    
    def toObject(self) -> dict:
        o = {
            'appId': self.app_id,
            'userId': self.userId,
            'onboardingToken': self.onboardingToken,
            'refreshToken': self.refreshToken,
            'xAuthToken': self.xAuthToken,
            'persistentDeviceId': self.persistentDeviceId,
            'installId': self.installId,
            'userAgent': self.userAgent,
            'tinderVersion': self.tinderVersion,
            'appVersion': self.appVersion,
            'osVersion': self.osVersion,
            'platform': self.platform,
            'encodedDeviceModel': self.encodedDeviceModel,
            'encodedDeviceCarrier': self.encodedDeviceCarrier,
            'appsFlyerId': self.appsFlyerId,
            'language': self.language,
            'proxy': self.httpProxy
        }
        return o

    def toJSON(self) -> str:
        return json.dumps(self.toObject(), indent=2)

    @staticmethod
    def fromJSON(s: str) -> 'TinderClient':
        return TinderClient.fromObject(json.loads(s))

    def loadProxy():
        print("fetch proxy...")
        return None

    def getAppSessionTimeElapsed(self) -> float:
        self.app_seconds = time.time() - self.appSessionStartTime
        return self.app_seconds

    def getUserSessionTimeElapsed(self) -> float:
        if self.userSessionStartTime == 0:
            return None
        self.user_seconds = time.time() - self.userSessionStartTime
        return self.user_seconds

    def assignDecodedValues(self, response: dict):
        data = next(iter(response.values()))
        if type(data) is not dict:
            return
        
        if 'refresh_token' in data:
            self.refreshToken = data['refresh_token']
            if type(self.refreshToken) is dict:
                self.refreshToken = self.refreshToken['value']
            print("refresh_token: " + self.refreshToken)

        if 'user_id' in data:
            self.userId = data['user_id']
            if type(self.userId) is dict:
                self.userId = self.userId['value']
            print("userId: " + self.userId)

        if 'onboarding_token' in data:
            self.onboardingToken = data['onboarding_token']
            if type(self.onboardingToken) is dict:
                self.onboardingToken = self.onboardingToken['value']
            print("onboardingToken: " + self.onboardingToken)

        if 'auth_token' in data:
            self.xAuthToken = data['auth_token']
            if type(self.xAuthToken) is dict:
                self.xAuthToken = self.xAuthToken['value']
            print("xAuthToken: " + self.xAuthToken)
            self.onboardingToken = None  # registered
        
        if 'auth_token_ttl' in data:  # LoginResult login_result
            self.userSessionId = str(uuid.uuid4()).upper()
            self.userSessionStartTime = time.time()
            print("userSessionId: " + self.userSessionId)

    def _getHeaders_POST_Protobuf(self):
        headers = {
            "Accept": "application/x-protobuf",
            "persistent-device-id": self.persistentDeviceId,
            "User-Agent": self.userAgent,
            "encoded-device-carrier": self.encodedDeviceCarrier,
            "x-hubble-entity-id": str(uuid.uuid4()),
            "os-version": str(self.osVersion),
            "Locale": "en",
            "app-session-time-elapsed": None,
            "encoded-device-model": self.encodedDeviceModel,
            "Content-Length": None, # order
            "x-supported-image-formats": "webp, jpeg",
            "platform": self.platform,
            "install-id": self.installId,
            'appsflyer-id': self.appsFlyerId,
            "user-session-time-elapsed": None,
            'mobile-country-code': '',
            "Accept-Language": self.language,
            "tinder-version": self.tinderVersion,
            'funnel-session-id': self.funnelSessionId, # only: proto, onboarding
            'mobile-network-code': '',
            "Accept-Encoding": "gzip, deflate, br",
            "supported-auth-options": "apple,facebook,line,sms",
            "Content-Type": 'application/x-google-protobuf',
            "app-version": str(self.appVersion),
            "user-session-id": None,
            "app-session-id": None,
            #"X-Auth-Token": None, proto not include
        }

        # continue onboarding
        if self.xAuthToken:
            #headers['X-Auth-Token'] = self.xAuthToken
            headers['app-session-id'] = self.appSessionId
            headers["app-session-time-elapsed"] = f"{self.getAppSessionTimeElapsed()}"
            headers['user-session-id'] = self.userSessionId
            headers["user-session-time-elapsed"] = f"{self.getUserSessionTimeElapsed()}"
        else:
            headers['app-session-id'] = self.appSessionId
            headers["app-session-time-elapsed"] = f"{self.getAppSessionTimeElapsed()}"
        
        l = list(headers.items())
        r = random.randint(0, 1)
        if r == 1:
            index1 = [i for i, (k, _) in enumerate(l) if k == "User-Agent"][0]
            index2 = [i for i, (k, _) in enumerate(l) if k == "persistent-device-id"][0]
            tmp = l[index1]
            l[index1] = l[index2]
            l[index2] = tmp

        headers = dict(l)
        return headers

    def _getHeaders_POST_JSON(self):
        headers = {
            "os-version": str(self.osVersion),
            "persistent-device-id": self.persistentDeviceId,
            "User-Agent": self.userAgent,
            "support-short-video": None, # only: boot, leads
            "x-refresh-token": None,
            "x-hubble-entity-id": str(uuid.uuid4()), # ios only
            "app-session-time-elapsed": None,
            "Content-Length": None, # order
            "X-Auth-Token": None, # SWIPE
            "x-supported-image-formats": "webp, jpeg",
            "token": None, # ONBOARDING
            "platform": self.platform,
            "appsflyer-id": None, # ONBOARDING complete only
            "user-session-time-elapsed": None,
            "Accept-Language": self.language,
            "tinder-version": self.tinderVersion,
            "Accept": "application/json", # ios only
            "Content-Type": 'application/json; charset=UTF-8',
            "app-version": str(self.appVersion),
            "user-session-id": None,
            "funnel-session-id": None, # only: proto, onboarding
            "Accept-Encoding": "gzip, deflate, br",
            "app-session-id": None,
        }

        # continue onboarding
        if self.xAuthToken:
            headers['X-Auth-Token'] = self.xAuthToken
            headers['app-session-id'] = self.appSessionId
            headers["app-session-time-elapsed"] = f"{self.getAppSessionTimeElapsed()}"
            headers['user-session-id'] = self.userSessionId
            headers["user-session-time-elapsed"] = f"{self.getUserSessionTimeElapsed()}"
        elif self.onboardingToken:
            headers['app-session-id'] = self.appSessionId
            headers["app-session-time-elapsed"] = f"{self.getAppSessionTimeElapsed()}"
        
        ### random swap index
        l = list(headers.items())
        r = random.randint(0, 1)
        if r == 1:
            index1 = [i for i, (k, _) in enumerate(l) if k == "app-session-id"][0]
            index2 = [i for i, (k, _) in enumerate(l) if k == "os-version"][0]
            tmp = l[index1]
            l[index1] = l[index2]
            l[index2] = tmp
        headers = dict(l)

        return headers

    def _getHeaders_GET_JSON(self):
        headers = self._getHeaders_POST_JSON()
        headers.pop("Content-Type", None)
        headers.pop("Content-Length", None)
        return headers

    # fake appId to pass ios_device_token check
    def _get_appId(phoneNumber: str):
        #return "825DDA558L.com.cardify.tinder"
        return "825DDA558L.com.cardify.tinder" + phoneNumber

    def _request(self, method: str, url: str, headers: dict, data: bytes = None, http_version=None, retry=0) -> bytes:
        try:
            response = http_async_sesion.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                proxy=self.httpProxy,
                http_version=http_version,
                timeout=60*5 # 300 seconds (better for photo upload)
            )

            self.last_status_code = response.status_code
            print("CALL_STATUS: " + str(response.status_code))

            return response.content
        except Exception as e:
            print(e)
            #logger.error(json.dumps(error, indent=2))
            if retry < 1:
                retry = retry + 1

                print(">> New proxy")
                self.httpProxy = TinderClient.loadProxy()
                print(self.checkIp())
                return self._request(method, url, headers, data, http_version, retry)
            else:
                return None

    ### Init
    def sendBuckets(self):
        url = "https://api.gotinder.com/v2/buckets"
        bodyBytes = b'{"experiments":[], "device_id":' + json.dumps(self.installId).encode() + b'}'
        
        headers = self._getHeaders_POST_JSON()
        headers.pop('X-Auth-Token', None)
        headers.pop('app-session-id', None)
        headers.pop('app-session-time-elapsed', None)
        headers.pop('user-session-id', None)
        headers.pop('user-session-time-elapsed', None)

        response = self._request("POST", url, headers, bodyBytes)

        return json.loads(response)

    def healthCheckAuth(self) -> dict:
        url = "https://api.gotinder.com/healthcheck/auth"
        headers = {
            "x-supported-image-formats": "webp, jpeg",
            "Accept": "application/json", # ios only
            "x-hubble-entity-id": str(uuid.uuid4()), # ios only
            "tinder-version": self.tinderVersion,
            "app-version": str(self.appVersion),
            "persistent-device-id": self.persistentDeviceId,
            "Accept-Language": self.language,
            "platform": self.platform,
            "Accept-Encoding": "gzip, deflate, br",
            "app-session-time-elapsed": f"{self.getAppSessionTimeElapsed()}",
            "User-Agent": self.userAgent,
            "app-session-id": self.appSessionId,
            "os-version": str(self.osVersion),
            #"platform-variant": self.platformVariant, # android only
            #"store-variant": self.storeVariant, # android only
            #"x-device-ram": self.x_device_ram, # android only
            ### ios not include (its move to _call)
            # "install-id": self.installId,
            # "encoded-device-model": self.encodedDeviceModel,
            # "encoded-device-carrier": self.encodedDeviceCarrier,
            # "mobile-country-code": str(self.mobileCountryCode),
            # "mobile-network-code": str(self.mobileNetworkCode),
        }

        response = self._request("GET", url, headers)

        return json.loads(response)
    
    def checkIp(self):
        response = http_async_sesion.request(
            method="GET",
            url="https://api64.ipify.org?format=text",
            proxy=self.httpProxy
        )
        
        r = response.text
        return r

    def getLocation(self, ip: str= None):
        if ip is None:
            ip = self.checkIp()
        
        bodyBytes = b'{"search":"' + ip.encode() + b'"}'
        response = http_async_sesion.request(
            method="POST",
            url="https://geo.ipify.org/api/web",
            proxy=self.httpProxy,
            data=bodyBytes
        )
        
        r = response.json()
        lat = r['location']['lat']
        lng = r['location']['lng']

        return lat, lng

    ### PROTO: TODO: blackboxprotobuf => protoc
    def authLogin(self, phoneNumber: str):
        appId = TinderClient._get_appId(phoneNumber)
        self.app_id = appId

        bodyBytes = blackboxprotobuf.encode_message({
            "phone": {
                "phone": phoneNumber,
                # "ios_device_token": {
                #     "value": generateDeviceToken(appId) # StringValue
                # }
            }
        }, message_type="AuthGatewayRequest", config=config)
        print('AuthGatewayRequest (authLogin)')

        headers = self._getHeaders_POST_Protobuf()
        response = self._request("POST", "https://api.gotinder.com/v3/auth/login", headers, bodyBytes)

        decoded = blackboxprotobuf.decode_message(response, message_type="AuthGatewayResponse", config=config)[0]
        return decoded

    def verifyOtp(self, phoneNumber: str, otp: str):
        bodyBytes = blackboxprotobuf.encode_message({
            "phone_otp": { # phoneOtp => phone_otp
                "phone": {
                    "value": phoneNumber
                }, # StringValue
                "otp": otp
            }
        }, message_type="AuthGatewayRequest", config=config)
        print('AuthGatewayRequest (verifyOtp): ' + bodyBytes.hex())

        headers = self._getHeaders_POST_Protobuf()
        response = self._request("POST", "https://api.gotinder.com/v3/auth/login", headers, bodyBytes)

        decoded =  blackboxprotobuf.decode_message(response, message_type="AuthGatewayResponse", config=config)[0]
        self.assignDecodedValues(decoded)
        return decoded
    
    # login only
    def verifyEmail(self, otp: str):
        bodyBytes = blackboxprotobuf.encode_message({
            "email_otp": { # emailOtp => email_otp
                "refresh_token": { # refreshToken => refresh_token
                    "value": self.refreshToken,
                },
                "otp": otp
            }
        }, message_type="AuthGatewayRequest", config=config)
        print('AuthGatewayRequest (verifyEmail): ' + bodyBytes.hex())

        headers = self._getHeaders_POST_Protobuf()
        response = self._request("POST", "https://api.gotinder.com/v3/auth/login", headers, bodyBytes)

        decoded =  blackboxprotobuf.decode_message(response, message_type="AuthGatewayResponse", config=config)[0]
        self.assignDecodedValues(decoded)
        return decoded
    # register only
    def useEmail(self, email: str):
        bodyBytes = blackboxprotobuf.encode_message({
            "email": {
                "email": email,
                "refresh_token": { # refreshToken => refresh_token
                    "value": self.refreshToken,
                }
            }
        }, message_type="AuthGatewayRequest", config=config)
        print('AuthGatewayRequest (useEmail): ' + bodyBytes.hex())

        headers = self._getHeaders_POST_Protobuf()
        response = self._request("POST", "https://api.gotinder.com/v3/auth/login", headers, bodyBytes)

        decoded =  blackboxprotobuf.decode_message(response, message_type="AuthGatewayResponse", config=config)[0]
        self.assignDecodedValues(decoded)
        return decoded
    
    def dismissSocialConnectionList(self):
        bodyBytes = blackboxprotobuf.encode_message({
            "dismiss_social_connection_list": {
                "refresh_token": self.refreshToken # refreshToken => refresh_token
            }
        }, message_type="AuthGatewayRequest", config=config)
        print('AuthGatewayRequest (dismiss_social_connection_list): ' + bodyBytes.hex())

        headers = self._getHeaders_POST_Protobuf()
        response = self._request("POST", "https://api.gotinder.com/v3/auth/login", headers, bodyBytes)

        decoded =  blackboxprotobuf.decode_message(response, message_type="AuthGatewayResponse", config=config)[0]
        self.assignDecodedValues(decoded)
        return decoded

    def getAuthToken(self):
        ### with STANDARD
        # obj, tdf = blackboxprotobuf.decode_message(base64.decodebytes(b'UlIKUGV5SmhiR2NpT2lKSVV6STFOaUo5Lk1UTXdNekkxTnpZNE16ay42RmNiRFpENWJmQjJOOTctamNYVnRLVVZUcUpBWTRxUi1kMEFRYkJnUkdJugEKCghTVEFOREFSRA=='), message_type="AuthGatewayRequest", config=config)
        # obj['refresh_auth']['refresh_token'] = self.refreshToken
        # bodyBytes = blackboxprotobuf.encode_message(obj, tdf)

        bodyBytes = blackboxprotobuf.encode_message({
            "refresh_auth": { # refreshAuth => refresh_auth
                "refresh_token": self.refreshToken # refreshToken => refresh_token
            }
        }, message_type="AuthGatewayRequest", config=config)
        print('AuthGatewayRequest (getAuthToken): ' + bodyBytes.hex())

        headers = self._getHeaders_POST_Protobuf()
        response = self._request("POST", "https://api.gotinder.com/v3/auth/login", headers, bodyBytes)

        decoded =  blackboxprotobuf.decode_message(response, message_type="AuthGatewayResponse", config=config)[0]
        self.assignDecodedValues(decoded)
        return decoded
    
    def _merge_onboardingPayload(self, field: dict):
        for i, old in enumerate(self.onboardingPayload):
            if old['name'] == field['name']:
                self.onboardingPayload[i] = field
                return
        self.onboardingPayload.append(field)

    ### JSON flows: onboarding
    def _onboarding_set(self, bodyBytes):
        if bodyBytes:
            # merge with previous
            obj = json.loads(bodyBytes)
            fields: list[dict]= obj['fields']
            if len(self.onboardingPayload) == 0:
                self.onboardingPayload = fields
            else:
                for field in fields:
                    self._merge_onboardingPayload(field)
                obj['fields'] = self.onboardingPayload
                bodyBytes = json.dumps(obj).encode()
        else:
            bodyBytes = json.dumps({
                "fields": self.onboardingPayload
            }).encode()

        headers = self._getHeaders_POST_JSON()
        headers.update({
            "token": self.onboardingToken,
            "funnel-session-id": self.funnelSessionId,
            #'appsflyer-id': None # remove it
        })
        response = self._request("POST", self.URL_ONBOARDING, headers, bodyBytes)
        
        print(json.dumps(json.loads(response)['meta']))

        return response

    def endOnboarding(self):
        bodyBytes = b'{"fields":[]}'

        headers = self._getHeaders_POST_JSON()
        headers.update({
            "token": self.onboardingToken,
            'x-refresh-token': self.refreshToken,
            "funnel-session-id": self.funnelSessionId,
            'appsflyer-id': self.appsFlyerId,
        })
        response = self._request("POST", self.URL_ONBOARDING_COMPLETE, headers, bodyBytes)
        
        print(json.dumps(json.loads(response)['meta']))

        return response

    def startOnboarding(self):
        headers = self._getHeaders_GET_JSON()
        headers.update({
            "token": self.onboardingToken,
            "funnel-session-id": self.funnelSessionId
            #'appsflyer-id': None # remove it
        })
        response = self._request("GET", self.URL_ONBOARDING, headers)

        print(json.dumps(json.loads(response)['meta']))
        
        return response

    ### Skip (send previous payload)
    def onboardingSkip(self):
        return self._onboarding_set(None)

    ### One payload fill all
    def onboardingSuper(self, name: str, dob: str, gender: int, interested_in_gender: list[int]):        
        bodyStr = b'{"fields":[{"name":"name","data":' + json.dumps(name).encode() + b'},{"data":"' + dob.encode() + b'","name":"birth_date"},{"data":' + str(gender).encode() + b',"name":"gender"},{"name":"show_orientation_on_profile","data":true},{"name":"tinder_rules","data":{"checked":true}},{"name":"sexual_orientations","data":[{"checked":true,"description":"A person who is exclusively attracted to members of the opposite gender","name":"Straight","id":"str"},{"name":"Gay","checked":false,"id":"gay","description":"An umbrella term used to describe someone who is attracted to members of their gender"},{"id":"les","description":"A woman who is emotionally, romantically, or sexually attracted to other women","name":"Lesbian","checked":true},{"description":"A person who has potential for emotional, romantic, or sexual attraction to people of more than one gender","name":"Bisexual","id":"bi","checked":true},{"name":"Asexual","id":"asex","checked":false,"description":"A person who does not experience sexual attraction"},{"id":"demi","description":"A person who does not experience sexual attraction unless they form a strong emotional connection","checked":false,"name":"Demisexual"},{"name":"Pansexual","id":"pan","description":"A person who has potential for emotional, romantic, or sexual attraction to people regardless of gender","checked":false},{"id":"qur","name":"Queer","description":"An umbrella term used to express a spectrum of sexual orientations and genders often used to include those who do not identify as exclusively heterosexual","checked":false},{"id":"ques","checked":false,"name":"Questioning","description":"A person in the process of exploring their sexual ZZZZZ"}]},{"data":' + json.dumps(interested_in_gender).encode() + b',"name":"interested_in_gender"}]}'
        bodyStr = bodyStr.replace(b'ZZZZZ', base64.b64decode('b3JpZW50YXRpb24gYW5kXC9vciBnZW5kZXI=')) # orientation and\/or gender

        return self._onboarding_set(bodyStr)

    ### Step by step
    def setTinderRules(self):
        # TODO: GET URL_ONBOARDING => parse tinder_rules (value: body, title)
        #bodyBytes = b'{"fields":[{"data":{"body":"Please follow these House Rules.","checked":true,"title":"Welcome to Tinder."},"name":"tinder_rules"}]}'
        bodyBytes = b'{"fields":[{"name":"tinder_rules","data":{"checked":true}}]}' # ios style
        return self._onboarding_set(bodyBytes)

    def setName(self, value: str):
        #bodyBytes = b'{"fields":[{"data":"Chris","name":"name"}]}'
        bodyBytes = b'{"fields":[{"data":' + json.dumps(value).encode() + b',"name":"name"}]}'

        return self._onboarding_set(bodyBytes)

    def setBirthDate(self, value: str):
        #bodyBytes = b'{"fields":[{"data":"1999-12-27","name":"birth_date"}]}'
        bodyBytes = b'{"fields":[{"data":' + json.dumps(value).encode() + b',"name":"birth_date"}]}'

        return self._onboarding_set(bodyBytes)

    def setGender(self, value: int):
        #bodyBytes = b'{"fields":[{"data":1,"name":"gender"},{"name":"custom_gender"},{"data":true,"name":"show_gender_on_profile"}]}'
        bodyBytes = b'{"fields":[{"data":' + json.dumps(value).encode() + b',"name":"gender"},{"name":"custom_gender"},{"data":true,"name":"show_gender_on_profile"}]}'

        return self._onboarding_set(bodyBytes)

    # required=False
    def setInterestedInGender(self, value: list[int]):
        #bodyBytes = b'{"fields":[{"data":[0],"name":"interested_in_gender"},{"data":{"checked":false,"should_show_option":false},"name":"show_same_orientation_first"}]}'
        bodyBytes = b'{"fields":[{"data":' + json.dumps(value).encode() + b',"name":"interested_in_gender"},{"data":{"checked":false,"should_show_option":false},"name":"show_same_orientation_first"}]}'

        return self._onboarding_set(bodyBytes)

    # required=False
    def setInterestedInGenders(self, value):
        pass

    # required=False
    def setRelationshipIntent(self):
        bodyBytes = b'{"fields":[{"data":{"selected_descriptors":[{"choice_selections":[{"id":"1"}],"id":"de_29"}]},"name":"relationship_intent"}]}'
        #bodyBytes = b'{"fields":[{"data":' + json.dumps(value).encode() + b',"name":"interested_in_gender"},{"data":{"checked":false,"should_show_option":false},"name":"show_same_orientation_first"}]}'

        return self._onboarding_set(bodyBytes)

    def setDistanceFilter(self):
        bodyBytes = b'{"fields":[{"data":50,"name":"distance_filter"}]}'

        return self._onboarding_set(bodyBytes)

    ### Upload
    def onboardingPhoto(self, data: bytes, total_image):
        url = self.URL_ONBOARDING_PHOTO
        filename = str(uuid.uuid4()).upper() + ".jpg"
        boundary = "Boundary-" + str(uuid.uuid4()).upper()

        total_image = total_image - 1 # 2nd image => num_pending_media => uploadPhoto
        contentType = "multipart/form-data; boundary=" + boundary
        bodyBytes = b'--' + boundary.encode() + b'\r\nContent-Disposition: form-data; name="photo"; filename="' + filename.encode() + b'"\r\nContent-Type: image/jpeg\r\nContent-Length: ' + str(len(data)).encode() + b'\r\n\r\n' + data + b'\r\n--' + boundary.encode() + b'\r\nContent-Disposition: form-data; name="num_pending_media"\r\nContent-Transfer-Encoding: binary\r\nContent-Type: application/json; charset=UTF-8\r\nContent-Length: 1\r\n\r\n' + str(total_image).encode() + b'\r\n--' + boundary.encode() + b'--'
        bodyBytes = b'--' + boundary.encode() + b'\r\nContent-Disposition: form-data; name="type"\r\n\r\nphoto\r\n' + bodyBytes

        #self.httpProxy = "http://127.0.0.1:8888" # debug

        http_version=2 # HTTP 1.1 (prevent HTTP2 framing layer error)
        headers = self._getHeaders_POST_JSON()
        headers.update({
            "Content-Type": contentType,
            "token": self.onboardingToken,
            "funnel-session-id": self.funnelSessionId
            #'appsflyer-id': None # remove it
        })
        response = self._request("POST", url, headers, bodyBytes, http_version)
        
        try:
            print(json.dumps(json.loads(response)['meta']))
        except:
            response = self.onboardingPhoto(data, total_image + 1)
        
        return response

    def uploadPhoto(self, data: bytes, media_id: str):
        url = "https://api.gotinder.com/mediaservice/photo"
        filename = str(uuid.uuid4()).upper()
        boundary = str(uuid.uuid4()).upper()

        contentType = "multipart/form-data; boundary=" + boundary
        bodyBytes = b'--' + boundary.encode() + b'\r\nContent-Disposition: form-data; name="image"; filename="' + filename.encode() + b'"\r\nContent-Type: image/jpeg\r\nContent-Length: ' + str(len(data)).encode() + b'\r\n\r\n' + data + b'\r\n--' + boundary.encode() + b'--'
        
        #self.httpProxy = "http://127.0.0.1:8888" # debug

        http_version=2 # HTTP 1.1 (prevent HTTP2 framing layer error)
        headers = self._getHeaders_POST_JSON()
        headers.update({
            "Content-Type": contentType,
            "x-media-id": media_id,
            #'appsflyer-id': None # remove it
        })
        response = self._request("POST", url, headers, bodyBytes, http_version)
        
        return response
    
    #### JSON
    def updateLocation(self, lat: float, lon: float):
        url = "https://api.gotinder.com/v2/meta"
        bodyBytes = b'{"lat":' + json.dumps(lat).encode() + b',"lon":' + json.dumps(lon).encode() + b',"background":false,"force_fetch_resources":true}'
        print('updateLocation: ' + bodyBytes.decode())

        headers = self._getHeaders_POST_JSON()
        response = self._request("POST", url, headers, bodyBytes)

        print(json.dumps(json.loads(response)['meta']))
        return response
    
    def updateLocalization(self, lat: float, lon: float):
        url = "https://api.gotinder.com/v2/rosetta/localization"
        bodyBytes = b'{"lat":' + json.dumps(lat).encode() + b',"lon":' + json.dumps(lon).encode() + b',"locale":"en","keys":["rosetta_test_string","coins_2_0_intro_modal_title","coins_2_0_intro_modal_get_coins_cta","coins_2_0_intro_modal_earn","coins_2_0_intro_modal_use","coins_2_0_intro_modal_stock_up","permissions.push_soft_prompt_main_text","permissions.push_soft_prompt_detail_text","permissions.push_soft_prompt_primary_button_title","permissions.push_soft_prompt_secondary_button_title","selfie_v2_biometric_consent_description_one","selfie_v2_biometric_consent_description_two","selfie_v2_modal_unverify_description"]}'
        print('updateLocalization: ' + bodyBytes.decode())

        headers = self._getHeaders_POST_JSON()
        response = self._request("POST", url, headers, bodyBytes)

        print(json.dumps(json.loads(response)['meta']))
        return response

    def locInit(self):
        url = "https://api.gotinder.com/v1/loc/init"
        bodyBytes = b'{"deviceTime":' + str(int(time.time() * 1000)).encode() + b',"eventId":"' + str(uuid.uuid4()).upper().encode() + b'"}'

        headers = self._getHeaders_POST_JSON()
        response = self._request("POST", url, headers, bodyBytes)

        return response

    def updateActivityDate(self, sendTime = False):
        url = 'https://api.gotinder.com/updates?is_boosting=false'
        if sendTime:
            #s = datetime.utcnow().isoformat(timespec='milliseconds') + 'Z' # deprecated
            #s = datetime.now(timezone.utc).isoformat(timespec='milliseconds') + 'Z' # +00:00
            s = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
            bodyBytes = b'{"nudge":"true","last_activity_date":"' + s.encode() + b'"}'
        else:
            bodyBytes = b'{}' # first time it submit empty

        headers = self._getHeaders_POST_JSON()
        headers.update({
            'support-short-video': '1'
        })
        response = self._request("POST", url, headers, bodyBytes)
        
        return response
    
    def updateProfileLanguagePreferences(self):
        url = 'https://api.gotinder.com/v2/profile/user'
        bodyBytes = b'{"global_mode":{"display_language":"en","language_preferences":[{"language":"en","is_selected":true}]}}'

        headers = self._getHeaders_POST_JSON()
        response = self._request("POST", url, headers, bodyBytes)
        
        return response
    
    def updateProfileBio(self, bio: str):
        url = 'https://api.gotinder.com/v2/profile/user'
        bodyBytes = b'{"bio":' + json.dumps(bio).encode() + b'}'

        headers = self._getHeaders_POST_JSON()
        response = self._request("POST", url, headers, bodyBytes)

        print(json.dumps(json.loads(response)['meta']))
        
        return response

    def updateProfileJobTitle(self, jobTitle: str, jobCompany: str = None):
        url = 'https://api.gotinder.com/v2/profile/job'
        if jobCompany is str:
            bodyBytes = b'{"jobs":[{"company":{"name":' + json.dumps(jobCompany) + b',"displayed":true},"title":{"name":' + json.dumps(jobTitle).encode() + b',"displayed":true}}]}'
        else:
            bodyBytes = b'{"jobs":[{"company":{"displayed":false},"title":{"name":' + json.dumps(jobTitle).encode() + b',"displayed":true}}]}'
        # ^-- this include previous job company (if set first)

        headers = self._getHeaders_POST_JSON()
        response = self._request("POST", url, headers, bodyBytes)
        # {"jobs":[{"company":{"displayed":false},"title":{"name":"freelancer_test123","displayed":true}}]}

        print(json.dumps(json.loads(response)['meta']))
        
        return response
    
    def updateProfileJobCompany(self, jobCompany: str, jobTitle: str = None):
        url = 'https://api.gotinder.com/v2/profile/job'
        if jobTitle is str:
            bodyBytes = b'{"jobs":[{"company":{"name":' + json.dumps(jobCompany).encode() + b',"displayed":true},"title":{"name":' + json.dumps(jobTitle).encode() + b',"displayed":true}}]}'
        else:
            bodyBytes = b'{"jobs":[{"company":{"name":' + json.dumps(jobCompany).encode() + b',"displayed":true},"title":{"displayed":false}}]}'
        # {"jobs":[{"company":{"name":"company test","displayed":true},"title":{"name":"freelancer_test123","displayed":true}}]}
        # ^-- this include previous job title (if set first)

        headers = self._getHeaders_POST_JSON()
        response = self._request("POST", url, headers, bodyBytes)

        print(json.dumps(json.loads(response)['meta']))
        
        return response
    
    def autocompleteProfileSchool(self, value: str):
        q_value = urllib.parse.quote(value)
        url = 'https://api.gotinder.com/v2/profile/autocomplete?type=school&q=' + q_value
        headers = self._getHeaders_GET_JSON()
        response = self._request("GET", url, headers)
        # results = json.loads(response)["data"]["results"]
        # name = results[0]["name"]
        # id = results[0]["id"]
        # ^-- use this to get school name+id

        return response

    def updateProfileSchool(self, name: str, id: str = None):
        url = 'https://api.gotinder.com/v2/profile/school'
        if id is str:
            bodyBytes = b'{"schools":[{"name":' + json.dumps(name).encode() + b',"school_id":' + json.dumps(id).encode() + b',"displayed":true}]}'
        else:
            bodyBytes = b'{"schools":[{"name":' + json.dumps(name).encode() + b',"displayed":true}]}'
        ### name+id (dropdown, autocomplete) OR name (only)
        # {"schools":[{"name":"Mitchell College","school_id":"ope_139300","displayed":true}]}
        # {"schools":[{"name":"Mitchell","displayed":true}]}
        # ^--- we can set any school without id (TODO: school list)

        headers = self._getHeaders_POST_JSON()
        response = self._request("POST", url, headers, bodyBytes)

        print(json.dumps(json.loads(response)['meta']))
        
        return response

    def getProfileLiftStyleFields(self):
        url = 'https://api.gotinder.com/dynamicui/configuration/content?component_id=sec_1_bottom_sheet'
        headers = self._getHeaders_GET_JSON()
        headers["Accept"] = "application/x-protobuf"
        response = self._request("GET", url, headers)

        decoded = blackboxprotobuf.decode_message(response)[0]
        # fields = decoded["1"]["4"]["3"] # [de_3: Pets, de_22: Drinking, ...]
        # field0_id = fields[0]["1"] # id: de_3
        # field0_values = fields[0]["7"] # value: []
        # field0_value0_id = fields[0]["7"][0]['1'] # id: 1
        # field0_value0_value = fields[0]["7"][0]['2'] # value: Dog

        return decoded

    def updateProfileLiftStyle(self, bodyBytes: bytes = None):
        url = 'https://api.gotinder.com/v2/profile/user'
        if bodyBytes is None:
            bodyBytes = b'{"selected_descriptors_append":[{"choice_selections":[{"id":"1"}],"id":"de_3"},{"id":"de_22","choice_selections":[{"id":"8"}]},{"id":"de_11","choice_selections":[{"id":"1"}]},{"id":"de_10","choice_selections":[{"id":"4"}]},{"choice_selections":[{"id":"1"}],"id":"de_7"},{"choice_selections":[{"id":"1"}],"id":"de_4"},{"id":"de_17","choice_selections":[{"id":"1"}]}]}'
        # ^-- {"selected_descriptors_append":[{"choice_selections:[id:"1"], id:"de_3"}, ...}
        # descriptors_sec_1
        # de_3: Pets
        # [("1", "Dog"), ("2", "Cat"), ("3", "Reptile"), ("4", "Amphibian"), ...]
        # ^--- use getProfileLiftStyleFields to grab a list then build bodyBytes

        headers = self._getHeaders_POST_JSON()
        response = self._request("POST", url, headers, bodyBytes)

        print(json.dumps(json.loads(response)['meta']))
        
        return response

    def addNewProfilePhoto(self, data: bytes):
        # requestPhotoXMediaId
        url = 'https://api.gotinder.com/mediaservice/placeholders'
        bodyBytes = b'\x08\x01'
        headers = self._getHeaders_POST_Protobuf()
        response = self._request("POST", url, headers, bodyBytes)
        decoded = blackboxprotobuf.decode_message(response)[0]
        # ex response: blackboxprotobuf.decode_message(bytes.fromhex('0a1c0a0c08dd9299b80610fc97e6c701120c08dd9299b80610abc285c2018201260a2435636265373237642d383966362d343035622d613138372d316364636332656232623064'))
        media_id: str = decoded['16']['1']

        url = 'https://api.gotinder.com/mediaservice/details'
        # ex bodyBytes: blackboxprotobuf.decode_message(bytes.fromhex('0a2435636265373237642d383966362d343035622d613138372d316364636332656232623064120e1a080a0012001a00220022020801'))
        bodyBytes = b'\x0a\x24' + media_id.encode() + b'\x12\x0e\x1a\x08\x0a\x00\x12\x00\x1a\x00\x22\x00\x22\x02\x08\x01'
        response = self._request("PUT", url, headers, bodyBytes)
        #decoded = blackboxprotobuf.decode_message(response)[0] # no need

    def deviceCheck(self):
        headers = self._getHeaders_GET_JSON()
        response = self._request("GET", self.URL_DEVICE_CHECK, headers)

        obj = json.loads(response)
        print(response)

        if 'data' in obj:
            # obj = {
            #     "data": {
            #         "ios_device_token": generateDeviceToken(self.app_id),
            #         "version": 1
            #     }
            # } # old style
            obj = {
                "version": 1,
                "ios_device_token": generateDeviceToken(self.app_id)
            }
            bodyBytes = json.dumps(obj).encode()

            headers = self._getHeaders_POST_JSON()
            response = self._request("POST", self.URL_DEVICE_CHECK, headers, bodyBytes)
            
            print(response)
        else:
            print("deviceCheck SKIPPED")

    def exlist(self):
        url = 'https://api.gotinder.com/v2/profile/exlist'
        bodyBytes = b''
        headers = self._getHeaders_POST_JSON()
        response = self._request("POST", url, headers, bodyBytes)

        return response

    # Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148
    def challengeVerifyArkose(self, token: str, answer: str):
        url = 'https://api.gotinder.com/challenge/verify'
        bodyBytes = b'{"challenge_type":"arkose","challenge_token":"' + token.encode() + b'","challenge_answer":' + json.dumps(answer).encode() + b'}'

        headers = self._getHeaders_POST_JSON()
        response = self._request("POST", url, headers, bodyBytes)
        
        return response

    def getProfileInfo(self):
        url = 'https://api.gotinder.com/v2/profile?include=experiences,account,onboarding,campaigns,spotify,tappy_content,instagram,travel,paywalls,tutorials,notifications,available_descriptors,misc_merchandising,purchase,likes,plus_control,offerings,feature_access,super_likes,tinder_u,user,boost,contact_cards,email_settings,readreceipts'
        
        headers = self._getHeaders_GET_JSON()
        response = self._request("GET", url, headers)
        
        return response
    
    def getProfileMeter(self):
        url = 'https://api.gotinder.com/v2/profile?include=profile_meter'
        
        headers = self._getHeaders_GET_JSON()
        response = self._request("GET", url, headers)
        
        return response
    
    def getFastMatch(self):
        url = 'https://api.gotinder.com/v2/fast-match/count'
        
        headers = self._getHeaders_GET_JSON()
        response = self._request("GET", url, headers)

        return response
    
    ### BOT ENGINE
    def processCaptcha(self):
        """
        Handle the captcha challenge process.
        Returns True if captcha was processed successfully, False otherwise.
        """
        try:
            if self.last_status_code != 200:
                # Get auth token response
                r = self.getAuthToken()
                print('AuthToken Response:', json.dumps(r, indent=4))

                # Check if response contains error with challenge token
                if isinstance(r, dict) and 'error' in r:
                    error_data = r.get('error', {})
                    ban_reason = error_data.get('ban_reason', {})
                    ban_appeal = ban_reason.get('ban_appeal', {})
                    token = ban_appeal.get('challenge_token')

                    if token:
                        tokenUP = token.upper()
                        print('Token:', tokenUP)
                        print('https://192.168.1.188/zcaptcha.html?key=' + tokenUP)
                        answer = input("answer: ")
                        
                        # Verify the captcha
                        r = self.challengeVerifyArkose(token, answer)
                        print("Challenge verify response:", r)

                        # Try getting auth token again
                        r = self.getAuthToken()
                        print("Final auth response:", r)
                        return True
                    else:
                        print("No challenge token found in response")
                        return False
                else:
                    print("No error information found in response")
                    return False
            return False
        except Exception as e:
            print(f"Error during captcha processing: {str(e)}")
            return False

    def _ws_on_message(ws, message):
        print("_ws_on_message")
        print(message) # b'\x0f\xa0'

    def _ws_thread_async(self):
        headers = self._getHeaders_GET_JSON()
        headers["Origin"] = 'https://keepalive.gotinder.com'
        headers["Authorization"] = f'Token token="{self.xAuthToken}"'
        headers["Sec-WebSocket-Version"] = "13"
        headers["Sec-WebSocket-Key"] = base64.b64encode(os.urandom(16)).decode()
        

        http_async_sesion = Session(
            verify=False,
            default_headers=False,
            impersonate="safari17_2_ios",
            #http_version=2 # HTTP 1.1 (prevent HTTP2 framing layer error)
        )
        ws = http_async_sesion.ws_connect(
            url="wss://keepalive.gotinder.com/ws",
            headers=headers,
            on_message=TinderClient._ws_on_message
            #proxy=self.httpProxy
        )
        ws.run_forever()

    def _ws_thread(self):
        # loop = asyncio.new_event_loop()
        # asyncio.set_event_loop(loop)
        # loop.run_until_complete(TinderClient._ws_thread_async(self))
        # loop.close()

        headers = self._getHeaders_GET_JSON()
        headers["Origin"] = 'https://keepalive.gotinder.com'
        headers["Authorization"] = f'Token token="{self.xAuthToken}"'
        headers["Sec-WebSocket-Version"] = "13"
        headers["Sec-WebSocket-Key"] = base64.b64encode(os.urandom(16)).decode()
        with Session(
            verify=False,
            default_headers=False,
            impersonate="safari17_2_ios"
        ) as s:
            ws = s.ws_connect(
                url="wss://keepalive.gotinder.com/ws",
                headers=headers,
                on_message=TinderClient._ws_on_message,
                proxy=self.httpProxy
            )
            print("WS CONNECTED")
            ws.run_forever()

    def ws_connect(self):
        thread = Thread(target=TinderClient._ws_thread, args=[self])
        thread.start()