# APRS: Anomalous Phenomena Reporting System (Project Deck)

**Date:** 11-9-25
**Tagline:** A MUFON Fork

---

## Slide 1: Title Card
* **Project Name:** APRS (Anomalous Phenomena Reporting System)
* **Concept:** A MUFON Fork
* **Date:** 11-9-25

---

## Slide 2: Roadmap Phase 1
**Phase 1 Focus:**
* Data Collection, Data Display, and Investigation
* Training

---

## Slide 3: Submission Form UI (Mockup)
*Visual Description: A dark-themed mobile UI showing a night sky illustration with a house.*

**Required Data Fields:**
1.  **Name**
2.  **Date / Time**
3.  **Weather Conditions**
4.  **Shape**
5.  **Number of Witnesses**
6.  **Detailed Description** (Text Area)
7.  **File Upload** (Button)

---

## Slide 4: Platform Architecture
*Visual Description: A system diagram showing data flow between the user, the database, and external services.*

**Core Components:**
* **Storage:** S3 Style Cloud Storage (Images/Videos)
* **Database:** Central Database connected to three primary API Routes.

**Network Routes & Security:**
1.  **Public Website / Submission Backend:**
    * Connects to Database via API Route.
    * Protected by **WAF**.
    * Frontend: Ghost CMS & Potentially Auth Web Front End.
2.  **UFO Data API:**
    * Connects Database to Public Backend/Data Access.
    * Protected by **WAF**.
    * Exposes data to: Public Internet.
3.  **Phenom App Connector:**
    * Connects Database to "Phenom UAP App".
    * Protected by **WAF**.
    * Exposes data to: Public Internet.

---

## Slide 5: Revenue Generation Model
**Membership Tiers & Access Rights**

| Membership Tier | Access Privileges |
| :--- | :--- |
| **Free Member** | Access to data via UI, Newsletter, etc. |
| **Basic Paid Member** | Access to basic API calls (does not include image or video access). |
| **Premium Paid Member** | Unlimited API Access including images and video. |
| **Platinum Member** | Unlimited API Access + UAP Research AI + Exclusives. |

---

## Slide 6: Parallel Operations (Phase 1)
**Operational Goals:**
* Develop **Field Training Manual**.
* Identify and train **Initial Investigators**.
* **Investigation Scope:** Focus on investigating the "highest fidelity cases only" initially, while expanding the roster of investigators.

---

## Slide 7: Roadmap Phase 2
**Phase 2 Focus:**
* Data Enrichment
* Backend Automation and UX Improvements
* Expanded Investigations
* Potential Fundraising Events

---

## Slide 8: Data Enrichment & App Updates
**Key Features:**
* **Automated Enrichment:** Backend app to automatically enrich submissions by deconflicting with services like **FlightAware**, identifying local weather conditions, and checking for **Starlink**.
* **Geo-Notifications:** Notify submitters and members when a submission is received nearby.
* **Phenom Integration:** Integrate with "Phenom" to automatically collect optimal sensor data based on the devices involved.

---

## Slide 9: Investigative Updates & Growth
**Expansion Strategy:**
* **Publishing:** Release Investigation Guides/Books on proper topic investigation.
* **Leadership:** Expand to regional investigation leads, eventually scaling to per-state leads.
* **Media:** Publish educational Podcasts and YouTube videos.
* **Analysis:** Publish regular analysis of submission data with high-quality visualizations.
* **Partnerships:** Share data with partner groups (SCU, SOL, MUFON, etc.).
* **Government Sales:** Partner and sell opt-in data to US Gov Partners for training data and internal investigations.
* **Academic:** Highlight academic research done on the topic.

---

## Slide 10: Roadmap Phase 3
**Phase 3 Focus:**
* Continuous Iteration and Improvement.

---

## Slide 11: The Future and Beyond
**Long-term Goals:**
* **Correction:** Identify failures, weak points, and areas for improvement; implement corrective actions.
* **Growth:** Continue to expand membership and investigation capabilities.
* **Consulting:** Offer "for hire" investigations and consulting for public and private partners.

---

## Slide 12: End Card
* **Status:** Fin
