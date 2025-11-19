"""Clean up stuck jobs in the database"""
from storage import get_jobs, update_job
from pathlib import Path

DB_PATH = Path(__file__).parent / "reports" / "jobs.db"

# Get all jobs
jobs = get_jobs(DB_PATH)

print(f"Found {len(jobs)} total jobs\n")

for job in jobs:
    job_id = job['id']
    status = job['status']
    target = job.get('target', 'unknown')
    
    print(f"Job {job_id[:8]}: {target} - Status: {status}")
    
    # Fix any jobs stuck in "running" or "queued" state
    if status in ['running', 'queued']:
        print(f"  → Fixing stuck job, setting to 'failed'")
        update_job(DB_PATH, job_id, {"status": "failed"})

print("\n✅ Cleanup complete!")
