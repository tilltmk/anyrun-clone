"""
Configuration file for AnyRun Clone
"""

import os

# Application Settings
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///anyrun.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Upload Settings
    UPLOAD_FOLDER = 'uploads'
    RESULTS_FOLDER = 'results'
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB max file size

    # Allowed file extensions
    ALLOWED_EXTENSIONS = {
        'exe', 'dll', 'pdf', 'docx', 'xlsx', 'zip', 'rar',
        'js', 'vbs', 'bat', 'ps1', 'py', 'jar', 'apk', 'msi',
        'scr', 'com', 'pif', 'hta', 'cpl', 'msc'
    }

    # Analysis Settings
    ANALYSIS_TIMEOUT = 300  # 5 minutes max analysis time
    SCREENSHOT_INTERVAL = 5  # Take screenshot every 5 seconds
    MAX_SCREENSHOTS = 10

    # String Extraction
    MIN_STRING_LENGTH = 4
    MAX_STRINGS_PER_FILE = 1000

    # YARA Settings
    YARA_RULES_PATH = 'yara_rules/'
    ENABLE_YARA_SCANNING = True

    # Threat Intelligence
    ENABLE_THREAT_INTEL = False
    VIRUSTOTAL_API_KEY = os.environ.get('VT_API_KEY')

    # Export Settings
    ENABLE_PDF_EXPORT = False  # Requires additional dependencies
    ENABLE_JSON_EXPORT = True
    ENABLE_HTML_EXPORT = True

    # Performance
    MAX_CONCURRENT_ANALYSES = 5
    CLEANUP_OLD_SESSIONS_DAYS = 30


# Development Config
class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False


# Production Config
class ProductionConfig(Config):
    DEBUG = False
    TESTING = False
    # Override with production settings
    SECRET_KEY = os.environ.get('SECRET_KEY')  # MUST be set in production


# Testing Config
class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///test_anyrun.db'


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
