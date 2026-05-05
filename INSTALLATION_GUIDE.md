# Flask IDS System - Complete Installation Guide

**Project:** Intrusion Detection System (IDS) with Machine Learning  
**Framework:** Flask 3.1.2  
**Version:** 1.0  
**Last Updated:** May 5, 2026

---

## 📋 Table of Contents

1. [System Requirements](#system-requirements)
2. [Prerequisites](#prerequisites)
3. [Installation Steps](#installation-steps)
4. [Virtual Environment Setup](#virtual-environment-setup)
5. [Dependency Installation](#dependency-installation)
6. [Configuration](#configuration)
7. [Running the Application](#running-the-application)
8. [Verification](#verification)
9. [Troubleshooting](#troubleshooting)
10. [Quick Start Commands](#quick-start-commands)
11. [Project Structure](#project-structure)
12. [First Run Steps](#first-run-steps)

---

## 🖥️ System Requirements

### Supported Operating Systems
- **Windows** 10/11 (64-bit)
- **macOS** 10.15 or later
- **Linux** (Ubuntu 18.04+, Debian 10+, etc.)

### Hardware Requirements
- **Processor:** Multi-core processor (2+ cores recommended)
- **RAM:** Minimum 2GB, 4GB+ recommended
- **Disk Space:** 500MB+ for dependencies and database

### Software Requirements
- **Python:** 3.8 or higher (3.11+ recommended)
- **pip:** Package installer for Python
- **Git:** For version control (optional but recommended)
- **Terminal/Command Prompt:** For running commands

---

## ✅ Prerequisites

### 1. Verify Python Installation

**Windows:**
```powershell
python --version
```

**macOS/Linux:**
```bash
python3 --version
```

Expected output: `Python 3.x.x` (3.8 or higher)

### 2. Verify pip Installation

**Windows:**
```powershell
pip --version
```

**macOS/Linux:**
```bash
pip3 --version
```

Expected output: `pip x.x.x from ... (python 3.x)`

### 3. Download Python (if needed)

Visit: **https://www.python.org/downloads/**

- Download Python 3.11 or later
- During installation, **IMPORTANT:** Check the box: `Add Python to PATH`
- Select "Install for all users"
- Click "Install Now"

### 4. Create Project Directory

If you haven't already:

**Windows:**
```powershell
mkdir c:\Users\user\Desktop\flask_project
cd c:\Users\user\Desktop\flask_project
```

**macOS/Linux:**
```bash
mkdir -p ~/Desktop/flask_project
cd ~/Desktop/flask_project
```

---

## 🚀 Installation Steps

### Step 1: Navigate to Project Directory

**Windows:**
```powershell
cd c:\Users\user\Desktop\flask_project
```

**macOS/Linux:**
```bash
cd ~/Desktop/flask_project
```

### Step 2: Create Python Virtual Environment

A virtual environment isolates project dependencies from your system Python.

**Windows:**
```powershell
python -m venv flask_venv
```

**macOS/Linux:**
```bash
python3 -m venv flask_venv
```

**Expected output:**
```
(No output on success - directory 'flask_venv' is created)
```

### Step 3: Activate Virtual Environment

**Windows (PowerShell):**
```powershell
flask_venv\Scripts\Activate.ps1
```

**Windows (Command Prompt):**
```cmd
flask_venv\Scripts\activate.bat
```

**macOS/Linux (Bash/Zsh):**
```bash
source flask_venv/bin/activate
```

**Expected output:**
```
(flask_venv) C:\Users\user\Desktop\flask_project>  # Windows
(flask_venv) user@machine flask_project %          # macOS/Linux
```

Notice the `(flask_venv)` prefix in your terminal - this indicates the virtual environment is active.

---

## 📦 Virtual Environment Setup

### Understanding Virtual Environments

A Python virtual environment is a self-contained directory tree that contains:
- A specific Python interpreter
- Libraries and dependencies
- Scripts and tools

**Benefits:**
- ✅ Isolates project dependencies
- ✅ Prevents version conflicts
- ✅ Easy to replicate on other machines
- ✅ Safe to uninstall via directory deletion

### Virtual Environment Locations

**Windows:**
- `flask_venv\Scripts\python.exe` - Python executable
- `flask_venv\Scripts\pip.exe` - pip executable
- `flask_venv\Lib\site-packages\` - Installed packages

**macOS/Linux:**
- `flask_venv/bin/python` - Python executable
- `flask_venv/bin/pip` - pip executable
- `flask_venv/lib/python3.x/site-packages/` - Installed packages

### Verify Virtual Environment

```powershell
# Windows
python -c "import sys; print(sys.prefix)"

# Should output: C:\Users\user\Desktop\flask_project\flask_venv
```

---

## 📥 Dependency Installation

### Step 1: Ensure Virtual Environment is Active

You should see `(flask_venv)` in your terminal prompt.

### Step 2: Upgrade pip (Recommended)

**Windows:**
```powershell
python -m pip install --upgrade pip
```

**macOS/Linux:**
```bash
python3 -m pip install --upgrade pip
```

### Step 3: Install Required Packages

Navigate to the `flask_venv` directory and install dependencies:

```powershell
cd flask_venv
pip install -r requirements.txt
```

**Expected output (sample):**
```
Collecting Flask==3.1.2
  Downloading Flask-3.1.2-py3-none-any.whl (101 kB)
  Installing collected packages: Flask, scikit-learn, numpy, pandas
Successfully installed Flask-3.1.2 scikit-learn-1.3.2 numpy-1.24.3 pandas-2.0.3
```

### Step 4: Verify Installation

```powershell
pip list
```

**Expected packages in output:**
```
Flask                    3.1.2
scikit-learn             1.3.2
numpy                    1.24.3
pandas                   2.0.3
Werkzeug                 (auto-installed)
Jinja2                   (auto-installed)
```

### Dependency Specifications

| Package | Version | Purpose |
|---------|---------|---------|
| Flask | 3.1.2 | Web framework |
| scikit-learn | 1.3.2 | Machine Learning models |
| numpy | 1.24.3 | Numerical computing |
| pandas | 2.0.3 | Data processing |

---

## ⚙️ Configuration

### Step 1: Database Initialization

The database is automatically initialized when you first run the application. It creates:

- `ids_system.db` - Main SQLite database with 4 tables:
  - `users` - User accounts (admin, users)
  - `network_traffic` - Collected traffic samples
  - `detection_events` - Detected anomalies
  - `model_metrics` - ML model performance data
  - `activity_logs` - Security event logs

### Step 2: Configure Application Settings

**File:** [flask_venv/app.py](flask_venv/app.py#L20)

Edit the Flask secret key (line ~20):

```python
# BEFORE (DO NOT USE IN PRODUCTION):
app.secret_key = 'REPLACE_WITH_STRONG_SECRET_KEY_12345'

# AFTER (Generate a secure key):
# Option 1: Use Flask generate
import secrets
app.secret_key = secrets.token_hex(32)

# Option 2: Use a random string
app.secret_key = 'your-long-random-string-here-minimum-32-chars'
```

### Step 3: Environment Variables (Optional)

Create a `.env` file in `flask_venv/` directory:

```
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
DEBUG=True
PORT=5000
```

---

## 🏃 Running the Application

### Step 1: Ensure Virtual Environment is Active

```powershell
# Check for (flask_venv) prefix in terminal
# If not active:
flask_venv\Scripts\Activate.ps1  # Windows PowerShell
# OR
flask_venv\Scripts\activate.bat  # Windows Command Prompt
```

### Step 2: Navigate to Flask Application Directory

```powershell
cd flask_venv
```

### Step 3: Start Flask Application

```powershell
python app.py
```

**Expected output:**
```
 * Serving Flask app 'app'
 * Debug mode: on
 * Running on http://localhost:5000
 * Press CTRL+C to quit
```

### Step 4: Access Application

Open your web browser and navigate to:

```
http://localhost:5000
```

You should see the **IDS Dashboard** login page.

### Alternative: Using Flask Built-in Command

```powershell
set FLASK_APP=app.py
flask run
```

---

## 🔍 Verification

### Verification Checklist

**1. Virtual Environment Active**
```powershell
# Should see (flask_venv) prefix
python -c "import sys; print('✓ VEnv Active' if 'flask_venv' in sys.prefix else '✗ VEnv Not Active')"
```

**2. All Packages Installed**
```powershell
pip list | findstr "Flask scikit-learn numpy pandas"
```

**3. Python Version Compatible**
```powershell
python -c "import sys; print(f'✓ Python {sys.version_info.major}.{sys.version_info.minor}' if sys.version_info >= (3,8) else '✗ Python < 3.8')"
```

**4. Flask Application Starts**
```powershell
cd flask_venv
python app.py
# Should display: Running on http://localhost:5000
```

**5. Database Initialized**
```powershell
# After running app, check:
dir ids_system.db  # Should exist
```

**6. Dashboard Accessible**
- Open browser: http://localhost:5000
- You should see the login page
- ✓ Verification complete!

---

## 🆘 Troubleshooting

### Issue 1: Python Not Found

**Error:**
```
'python' is not recognized as an internal or external command
```

**Solution:**
1. Verify Python is installed: Go to **Control Panel > Programs > Programs and Features**
2. If missing, download from https://www.python.org/downloads/
3. **Important:** Check "Add Python to PATH" during installation
4. Restart terminal/command prompt

**Alternative:** Use absolute path:
```powershell
C:\Python311\python --version
```

### Issue 2: Virtual Environment Fails to Activate

**Error:**
```
cannot be loaded because running scripts is disabled on this system
```

**Solution (Windows PowerShell):**
```powershell
# Allow script execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Then activate
flask_venv\Scripts\Activate.ps1
```

**Alternative:** Use Command Prompt instead:
```cmd
flask_venv\Scripts\activate.bat
```

### Issue 3: pip Install Fails

**Error:**
```
ERROR: Could not find a version that satisfies the requirement
```

**Solution:**
```powershell
# Update pip
python -m pip install --upgrade pip

# Try install again with verbose output
pip install -r requirements.txt -v

# If still fails, try one by one:
pip install Flask==3.1.2
pip install scikit-learn==1.3.2
pip install numpy==1.24.3
pip install pandas==2.0.3
```

### Issue 4: Flask Application Won't Start

**Error:**
```
Address already in use
```

**Solution:**
```powershell
# The port 5000 is already in use. Either:

# Option 1: Kill process using port 5000
# Windows - Find and stop process on port 5000
netstat -ano | findstr :5000

# Option 2: Change Flask port
# Edit app.py, line at bottom:
app.run(debug=True, port=5001)  # Use different port
```

### Issue 5: Import Errors (Module Not Found)

**Error:**
```
ModuleNotFoundError: No module named 'flask'
```

**Causes and Solutions:**

1. **Virtual environment not active:**
   ```powershell
   # Check for (flask_venv) prefix
   flask_venv\Scripts\Activate.ps1
   ```

2. **Packages not installed:**
   ```powershell
   pip install -r requirements.txt
   ```

3. **Wrong Python interpreter:**
   ```powershell
   # Verify you're using venv Python
   which python  # or 'where python' on Windows
   # Should show: flask_project\flask_venv\...
   ```

### Issue 6: Database Errors

**Error:**
```
sqlite3.OperationalError: database is locked
```

**Solution:**
1. Ensure only one Flask instance is running
2. Delete `ids_system.db` and restart (creates fresh database)
3. Restart terminal and Flask application

### Issue 7: Port 5000 Already Bound on macOS/Linux

**Solution:**
```bash
# Find process using port 5000
lsof -i :5000

# Kill process
kill -9 <PID>

# Or use different port
FLASK_ENV=development FLASK_APP=app.py FLASK_PORT=5001 flask run
```

---

## ⚡ Quick Start Commands

### Complete Fresh Installation (Windows PowerShell)

```powershell
# 1. Create and navigate to project
cd c:\Users\user\Desktop\flask_project

# 2. Create virtual environment
python -m venv flask_venv

# 3. Activate virtual environment
flask_venv\Scripts\Activate.ps1

# 4. Navigate to Flask directory
cd flask_venv

# 5. Install dependencies
pip install -r requirements.txt

# 6. Run application
python app.py
```

### Complete Fresh Installation (macOS/Linux Bash)

```bash
# 1. Create and navigate to project
mkdir -p ~/Desktop/flask_project
cd ~/Desktop/flask_project

# 2. Create virtual environment
python3 -m venv flask_venv

# 3. Activate virtual environment
source flask_venv/bin/activate

# 4. Navigate to Flask directory
cd flask_venv

# 5. Install dependencies
pip install -r requirements.txt

# 6. Run application
python app.py
```

### Quick Activation (When Re-opening Terminal)

**Windows:**
```powershell
flask_venv\Scripts\Activate.ps1; cd flask_venv; python app.py
```

**macOS/Linux:**
```bash
source flask_venv/bin/activate && cd flask_venv && python app.py
```

---

## 📂 Project Structure

```
flask_project/
│
├── INSTALLATION_GUIDE.md          ← You are here
├── DATASET_REPORT.md
├── PROJECT_FLOW_ANALYSIS.md
├── THESIS.md
│
├── datasets/
│   └── CIC-IDS2017/
│       └── cic_ids2017_balanced.csv
│
└── flask_venv/
    ├── app.py                     # Main Flask application
    ├── database.py                # SQLite database management
    ├── network_traffic.py         # Traffic simulation
    ├── ml_models.py               # Machine Learning models
    ├── logging_handler.py         # Activity logging
    ├── check_metrics.py           # Metrics checker
    ├── add_admin.py               # Admin user creator
    ├── QUICKSTART.py              # Quick start script
    ├── setup.py                   # Setup script
    │
    ├── requirements.txt           # Python dependencies
    ├── README.md                  # Technical documentation
    ├── IMPLEMENTATION_SUMMARY.md  # Implementation details
    ├── CHECKLIST.md              # Completion checklist
    │
    ├── templates/
    │   ├── admin_panel.html       # Admin dashboard
    │   ├── user_dashboard.html    # User dashboard
    │   ├── login.html             # Login page
    │   ├── index.html             # Home page
    │   ├── company.html           # Company info
    │   ├── pricing.html           # Pricing page
    │   └── signup.html            # Registration page
    │
    ├── static/
    │   ├── css/
    │   │   └── (CSS stylesheets)
    │   └── images/
    │       └── (Image assets)
    │
    ├── models/                    # Trained ML models
    │   └── (Model pickle files)
    │
    ├── ids_system.db              # SQLite database (auto-created)
    ├── ids_activity.log           # Activity log file
    │
    └── (Python environment directories)
        ├── Scripts/               # Windows executables
        ├── Lib/                   # Installed packages
        └── Include/               # C headers

```

---

## 🎬 First Run Steps

### Step 1: Login to Application

After running `python app.py` and opening http://localhost:5000:

**Default Admin Credentials:**
- **Username:** `admin`
- **Password:** `admin123`

**Note:** Change these credentials after first login!

### Step 2: Navigate Dashboard

The application has multiple sections:

1. **Dashboard Tab** - Overview of system statistics
2. **Models Tab** - ML model training and metrics
3. **Traffic Tab** - Network traffic analysis
4. **Events Tab** - Detection events
5. **Logs Tab** - Activity and audit logs
6. **Admin Panel** - User and system management

### Step 3: Collect Network Traffic

1. Go to **Models Tab**
2. Click **"Collect Traffic"** button
3. Wait for traffic collection to complete

### Step 4: Train ML Models

1. Click **"Train Models"** button
2. Wait for training to complete
3. View model metrics and performance

### Step 5: Activate Model

1. Select a model with highest F1-score
2. Click **"Activate"** button
3. Model is now ready for detection

### Step 6: Run Detection

1. Go to **Dashboard** or **Events Tab**
2. Click **"Run Detection"** button
3. View detected anomalies

---

## 📊 Key Files Reference

| File | Purpose | Location |
|------|---------|----------|
| `app.py` | Main Flask application with 20+ API endpoints | `flask_venv/` |
| `database.py` | SQLite database layer and CRUD operations | `flask_venv/` |
| `ml_models.py` | ML model training and inference | `flask_venv/` |
| `network_traffic.py` | Network traffic simulation | `flask_venv/` |
| `logging_handler.py` | Activity and security logging | `flask_venv/` |
| `requirements.txt` | Python package dependencies | `flask_venv/` |
| `templates/` | HTML templates (6 pages) | `flask_venv/templates/` |
| `static/` | CSS and image assets | `flask_venv/static/` |
| `ids_system.db` | SQLite database (auto-created) | `flask_venv/` |

---

## 🔐 Security Notes

### For Development Only

⚠️ **WARNING:** The default configuration is suitable for **development only**, NOT for production.

### Security Recommendations

1. **Change Secret Key**
   - Generate a strong random key
   - Store in environment variable
   - Never commit to version control

2. **Use HTTPS**
   - Install SSL certificate
   - Use `https://` instead of `http://`

3. **Database Security**
   - Backup database regularly
   - Use database encryption for sensitive data
   - Restrict database file permissions

4. **User Authentication**
   - Use strong passwords (minimum 8 characters)
   - Implement rate limiting
   - Enable account lockout after failed attempts

5. **API Endpoints**
   - Add authentication/authorization
   - Implement rate limiting
   - Validate all input data

---

## 📞 Support & Resources

### Documentation Files

- [README.md](flask_venv/README.md) - Technical overview
- [IMPLEMENTATION_SUMMARY.md](flask_venv/IMPLEMENTATION_SUMMARY.md) - Feature details
- [CHECKLIST.md](flask_venv/CHECKLIST.md) - Project completion status

### Useful Commands

```powershell
# View installed packages
pip list

# Show package info
pip show Flask

# Freeze current environment
pip freeze > requirements.txt

# Uninstall package
pip uninstall package-name

# Deactivate virtual environment
deactivate

# Remove virtual environment
rmdir /s flask_venv  # Windows
rm -rf flask_venv    # macOS/Linux
```

### External Resources

- **Flask Documentation:** https://flask.palletsprojects.com/
- **Python Documentation:** https://docs.python.org/3/
- **scikit-learn Guide:** https://scikit-learn.org/
- **pandas Documentation:** https://pandas.pydata.org/docs/

---

## ✅ Completion Checklist

After following this guide, you should have:

- [ ] Python 3.8+ installed
- [ ] Virtual environment created in `flask_venv/`
- [ ] Virtual environment activated (see `(flask_venv)` in terminal)
- [ ] All dependencies installed from `requirements.txt`
- [ ] Flask application runs without errors
- [ ] Database `ids_system.db` created
- [ ] Application accessible at `http://localhost:5000`
- [ ] Can login with admin credentials
- [ ] Dashboard displays without errors

**If all items are checked: ✅ Installation successful!**

---

## 🎉 Next Steps

1. **Explore the Dashboard**
   - Familiarize yourself with the UI
   - Check each tab and feature

2. **Collect Training Data**
   - Run traffic collection
   - Generate network samples

3. **Train ML Models**
   - Train all three models
   - Compare performance metrics

4. **Deploy Best Model**
   - Activate highest F1-score model
   - Run anomaly detection

5. **Monitor System**
   - Check detection events
   - Review activity logs

6. **Customize Configuration**
   - Modify detection parameters
   - Adjust logging levels
   - Configure alerts

---

**Installation Guide Version:** 1.0  
**Last Updated:** May 5, 2026  
**Status:** Complete and Ready for Use ✅

For questions or issues, refer to the troubleshooting section or consult the project documentation files.
