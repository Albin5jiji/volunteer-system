# Volunteer Identification System

A local biometric screening system for blood donation camps that prevents duplicate donor registrations using fingerprint verification. The application stores donor records, SecuGen fingerprint templates, screening attempts, donation visits, and fraud alerts in a SQLite database.

## Features

- Fingerprint-based donor identification using SecuGen biometric devices
- Prevents duplicate donor registrations and repeat donations
- Stores donor information in a normalized SQLite database
- Supports exact template lookup and biometric matching
- Configurable fingerprint matching threshold
- Maintains screening history, donation records, and fraud alerts
- Designed to fail safely if the biometric matcher is unavailable

---

## Technology Stack

- Backend: Python
- Database: SQLite
- Biometric Hardware: SecuGen Hamster HU20 / Pro20-AP
- Biometric API: SecuGen WebAPI
- Frontend: HTML, CSS, JavaScript

---

## Running the Application

Start the server:

powershell python app.py 

Open your browser and navigate to:

text http://localhost:8000 

The SQLite database is created automatically at:

text data/volunteer_system.db 

---

## SecuGen Configuration

Install the SecuGen driver and WebAPI service on the same computer that runs the application.

When a fingerprint is captured, the browser requests the local application to scan the fingerprint. The Python backend communicates with the SecuGen WebAPI.

### Fingerprint Capture

text https://localhost:8443/SGIFPCapture 

### Fingerprint Matching

text https://localhost:8443/SGIMatchScore 

If your SecuGen installation uses a different matching endpoint, specify it before starting the application:

powershell $env:VOLUNTEER_SECUGEN_MATCH_ENDPOINT="https://localhost:8443/SGIMatchScore" python app.py 

---

## License Configuration

By default, the application reads the SecuGen WebAPI license from:

text C:\Program Files\SecuGen\SgiBioSrv\sgiwebsrv.lic 

Alternatively, provide the license through an environment variable:

powershell $env:SECUGEN_LICENSE="your-license-string" 

---

## Matching Workflow

Every donor screening follows the same verification pipeline:

1. Capture the candidate's fingerprint.
2. Generate the fingerprint template.
3. Compute the template hash and search for an exact match.
4. If no exact match exists, compare the fingerprint against all active templates using the SecuGen matcher.
5. If the similarity score meets or exceeds the configured threshold, the donor is identified as an existing donor and registration is blocked.
6. Otherwise, the candidate may proceed with registration.

If fingerprint templates already exist but the biometric matcher is unavailable, the application does not automatically clear the candidate. This fail-safe prevents duplicate registrations because two scans of the same finger rarely produce identical template strings.

---

## Database Schema

The schema is defined in schema.sql.

| Table | Description |
|--------|-------------|
| donors | Stores donor personal and contact information |
| fingerprint_templates | Active fingerprint templates associated with donors |
| candidate_checks | Records every fingerprint verification attempt |
| donation_visits | Stores successful donations and blocked duplicate attempts |
| alerts | Logs duplicate detections and other warning events |

---

## Configuration

The following environment variables are supported:

powershell $env:PORT="8000" $env:VOLUNTEER_MATCH_THRESHOLD="80" $env:VOLUNTEER_DB="C:\path\to\volunteer_system.db" 

---

## Security Notes

Fingerprint templates are sensitive biometric information. For production deployments:

- Restrict access to the application host.
- Protect the SQLite database using appropriate file permissions.
- Secure the computer running the biometric scanner.
- Keep the SecuGen software and drivers up to date.
- Regularly back up the database.

---

## Project Structure

volunteer-system/ 
├── app.py 
├── schema.sql 
├── data/ 
│   └── volunteer_system.db 
├── static/ 
├── templates/ 
└── README.md
