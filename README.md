# Splunk Detection Engineering & Threat Hunting SOP

This SOP is for using the 10 detection engineering and threat hunting SPL queries provided in this repository. It explains how to:

- Save queries as **detection alerts** (detection engineering)
- Use queries manually for **threat hunting**
- Understand how each process works in both **free Splunk** and **Splunk Enterprise Security (ES)**

---

## 🛠️ Detection Engineering Workflow (Saving Alerts)

Detection Engineering is about building repeatable logic to automatically detect known threat behaviors. Here's how to do that in **any version of Splunk**.

### Step-by-Step: Creating a Saved Alert in Splunk

1. Go to the **Search** app (your main search bar)
2. Paste one of the SPL queries from the `/detections` folder
3. Click **Save As** ➜ **Alert**
4. Fill out the alert form:
   - **Title**: Name of the detection
   - **Trigger condition**: Example – "If number of results > 0"
   - **Time Range**: Choose a rolling time window
   - **Schedule**: Every 5 minutes / 15 minutes / hourly
   - **Severity**: Informational, Medium, High, etc.
   - **Alert Actions** (optional):
     - Email notification
     - Webhook
     - Splunk SOAR
     - Push to ticketing system
5. Click **Save**

🔁 Now your detection runs automatically on a schedule.

> ⚠️ **Important:** If you're using the **free version of Splunk**, the "Save As Alert" option is **disabled**. You will need a trial or paid version of Splunk Enterprise to save alerts.

> ✅ This simulates what Detection Engineers build in production. If you're using Splunk Enterprise Security (ES), you'd build this as a **Correlation Search**.

---

## 🧠 Threat Hunting Workflow (Manual Searching)

Threat hunting is the manual, proactive process of searching for signs of compromise or anomalies **before an alert fires**.

### Step-by-Step: Using a Query to Hunt

1. Go to the **Search** app
2. Paste a query from the `/detections` folder
3. Adjust the time picker (e.g., Last 24 hours)
4. Optionally adjust values:
   - `src_ip`
   - `username`
   - `host`
   - `commandLine`
5. Click **Search** and review the results





