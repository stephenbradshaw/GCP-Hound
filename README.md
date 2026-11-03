# ☁️ GCP-Hound - Google Cloud Security Attack Path Discovery Tool

<div align="center">

**🚀 Advanced GCP Attack Surface Analysis & Privilege Escalation Discovery**

<img width="238" height="197" alt="image" src="https://github.com/user-attachments/assets/cad67dc4-de8d-4c9e-abcf-af2742d0224d" />


[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![BloodHound Compatible](https://img.shields.io/badge/BloodHound-8.0+-red.svg)](https://bloodhound.specterops.io/)

*Visualize complex GCP attack paths with the power of BloodHound*

</div>

---

## Credits

GCP-Hound's BloodHound-compatible graph export feature relies on the excellent [bhopengraph](https://github.com/p0dalirius/bhopengraph/tree/main) library by [@p0dalirius](https://github.com/p0dalirius).

Many thanks to the author for providing an easy, schema-flexible way to generate and export complex attack graphs!

## 🎯 Overview

**GCP-Hound** is an open-source security enumeration and privilege escalation discovery tool designed specifically for Google Cloud Platform environments. Built to integrate seamlessly with **BloodHound's OpenGraph** framework, it transforms complex GCP IAM relationships into interactive attack graphs.

### Project Background

This project began as a personal learning journey into GCP-focused penetration testing and red teaming techniques. While GCP-Hound already provides substantial reconnaissance and analysis capabilities, it remains a work-in-progress tool that will continue evolving with new features and improvements over time.

The tool may currently lack many advanced features, but I'm committed to gradually improving and expanding its capabilities based on community feedback and real-world testing scenarios.

## Limitations

**Pathfinding**: Install the OpenGraph extension schema (`register_gcp_nodes.py`) before uploading exports. Without it, BloodHound treats the file as a generic graph (Cypher/search only). With the schema installed, traversable GCP abuse edges participate in CE pathfinding.
- **API Coverage**: GCP-Hound relies on Google Cloud APIs for enumeration. Some APIs or services may be disabled in target projects by default, resulting in partial data collection. Enabling additional APIs (e.g., via the gcloud CLI) may improve coverage, but this tool is strictly read-only and does not modify cloud configurations.
- **User and Group Enumeration**: Full directory listing needs Admin SDK Directory read (Users / Groups Read — **not** Workspace Super Admin) or Cloud Identity Groups read. Without that, GCP-Hound still materializes principals from IAM bindings (project/folder/org), but group membership edges will be incomplete.
- **Org / folder IAM**: `roles/browser`, `organizationViewer`, and `folderViewer` can see hierarchy but **cannot** call `getIamPolicy`. Org/folder bindings require `*.getIamPolicy` (e.g. `roles/iam.securityReviewer` or a custom role).
- **Environment Scope**: The tool has primarily been tested in lab and CTF settings. Results in large-scale or production GCP organizations may be incomplete or contain gaps.
- **Edge/Description Accuracy**: Some edge relationship descriptions are generated heuristically and may be imprecise in certain contexts due to the diversity of real-world GCP configurations.

## Required permissions (least privilege)

### GCP Resource Manager / IAM (org + folder + project bindings)

| Goal | Permission(s) | Practical role |
| --- | --- | --- |
| List orgs / folders / projects | `resourcemanager.*.get` / `list` | `roles/browser` or Viewer at org |
| **Read project IAM** | `resourcemanager.projects.getIamPolicy` | Project IAM Viewer / Security Reviewer |
| **Read folder IAM** | `resourcemanager.folders.getIamPolicy` | **Not** in `folderViewer` |
| **Read org IAM** | `resourcemanager.organizations.getIamPolicy` | **Not** in `organizationViewer` |
| Read IAM broadly (recommended) | all of the above (+ many service `getIamPolicy`) | `roles/iam.securityReviewer` at org |

Custom least-privilege role example (org scope):

```text
resourcemanager.organizations.get
resourcemanager.organizations.getIamPolicy
resourcemanager.folders.get
resourcemanager.folders.list
resourcemanager.folders.getIamPolicy
resourcemanager.projects.get
resourcemanager.projects.list
resourcemanager.projects.getIamPolicy
```

### Google Workspace / Cloud Identity directory

| Goal | What you need | Notes |
| --- | --- | --- |
| List users | Admin SDK **Users Read** (Admin API privilege) | Custom admin role is enough; Super Admin not required |
| List groups + members | Admin SDK **Groups Read** | Same — custom role OK |
| Groups without Workspace Admin | Cloud Identity Groups API (`groups.readonly` / Group Viewer) | Users still missing unless Users Read granted |
| OAuth scopes (user ADC) | `admin.directory.user.readonly`, `admin.directory.group.readonly`, `admin.directory.group.member.readonly` | Plus Cloud Identity groups scope if using that path |
| No directory access | — | Principals still appear from collected IAM members |

Without org/folder `getIamPolicy`, attack paths that start from org- or folder-level grants are invisible even if project IAM is fully collected.

## Known Issues

- Some edge types/descriptions are still experimental and may change.
- Parsing of large GCP environments can result in missed entities if project-level APIs are disabled or throttled.

---

##  Key Features

### **Current Capabilities (Implemented)**
* 🔍 **Comprehensive GCP Enumeration** – Projects, service accounts, storage buckets, BigQuery datasets, logging resources
* 👥 **Identity & Access Analysis** – Users, groups, Google Workspace integration
* 🚨 **Advanced Privilege Escalation Detection** – Service account key analysis, impersonation chains, and log access paths
* ☸️ **Container Security** – GKE cluster enumeration and Kubernetes RBAC analysis
* 🔐 **Secret Management** – Secret Manager enumeration and access analysis
* 💻 **Compute Infrastructure** – VM instances, disks, and compute resource discovery
* 🌐 **Network Mapping** – VPC, subnets, firewall rules, and network topology
* 🏢 **Organizational Structure** – Folder hierarchy and project organization mapping
* 📚 **Logging Resource Discovery** – Log sinks, log buckets, and log metrics with attack edge modeling
* 🎨 **Professional BloodHound Integration** – Custom GCP icons and OpenGraph compatibility

### **Future Enhancements (Planned)**
- [ ] **Pub/Sub Enumeration** - Topics, subscriptions, and messaging analysis
- [ ] **Cloud Functions Deep Analysis** - Serverless function security assessment

### 🚨 **Advanced Privilege Escalation Detection**
- Service Account Key Analysis – Detect dangerous key creation/management permissions
- Impersonation Chain Discovery – Map cross-account privilege escalation paths
- Log Privilege Analysis – Detect paths allowing unintended or CRITICAL access to logging resources (sinks, buckets, metrics, log streams)
- Risk-Based Scoring – CRITICAL, HIGH, MEDIUM risk classifications (currently not 100% accurate)
- Multi-Hop Attack Chains – Complex privilege escalation and log access paths

### 🎨 **Professional BloodHound Integration**
- **Custom GCP Icons** - Beautiful, distinct icons for each GCP resource type
- **OpenGraph Compatibility** - Full BloodHound v8.0+ support
- **Interactive Visualizations** - Explore attack paths through BloodHound's interface

## Installation & Setup

### **Prerequisites**
- Python 3.9 or higher
- Access to target GCP environment(s)
- BloodHound (8.0 or higher) Community Edition or Enterprise (optional, for visualization)

### **1. Clone Repository**

## Clone repository

```
git clone https://github.com/F41zK4r1m/GCP-Hound.git
cd GCP-Hound
```

## Create and activate virtual environment

```
python3 -m venv .venv
source .venv/bin/activate # On Windows: .venv\Scripts\activate
```

## Install dependencies

```
pip install -r requirements.txt
```

### **2. Configure GCP Authentication**

## Option A: Service Account Key

```
export GCP_CREDS="path/to/key.json"
```

## Option B: OAuth2 (Interactive)

```
gcloud auth application-default login
```


## Option C: Using gcloud CLI (Experimental Features)

```
gcloud auth login
```

### **3. BloodHound OpenGraph setup (required for pathfinding)**

Install the GCP-Hound **extension definition schema** (enables CE pathfinding on traversable abuse edges) and optional custom-node icons:

```
python3 register_gcp_nodes.py -s http://localhost:8080 -u admin -p password
```

This uploads `gcp-extension-schema.json` via `PUT /api/v2/extensions` and registers icons from `gcp-model.json`.

- ✅ Structured graph kinds (`GCP_ServiceAccount`, `GCP_CanCreateKeys`, …)
- ✅ Pathfinding on traversable abuse edges (`is_traversable: true`)
- ✅ Custom GCP icons in the BloodHound UI

Flags: `--extension-only`, `--icons-only`, `--extension-schema PATH`.

Re-collect after upgrading: exports now emit namespaced kinds that must match the installed schema.

---

## Usage

### **Basic Analysis**

### **4. Run GCP-Hound Analysis**

```
python3 gcp-hound.py
```

### Verbose output (recommended for first runs)

```
python3 gcp-hound.py -v
```

### Target specific project

```
python3 gcp-hound.py -p my-gcp-project
```

### Debug mode for troubleshooting

```
python3 gcp-hound.py -d
```

### Custom output directory

```
python3 gcp-hound.py -o /path/to/output
```

### Impersonate service account

```
python3 gcp-hound.py -i service@project.iam.gserviceaccount.com
```

### Quiet mode (minimal output)

```
python3 gcp-hound.py -q
```

### **4. Import to BloodHound**
- Generated file: `./output/gcp-bhopengraph.json`
- Upload via BloodHound UI file import
- Explore interactive attack graphs

---

### **Analysis Phases**

GCP-Hound performs analysis in **6 comprehensive phases**:

1. 🔍 **Authentication & Project Discovery** – Validate credentials and discover projects
2. 📊 **API Capability Assessment** – Determine available GCP APIs and permissions
3. 🗂️ **Resource Enumeration** – Discover service accounts, storage, BigQuery, GKE, compute, and logging resources
4. 🔐 **Privilege Analysis** – Analyze service account permissions, logging access, and key access capabilities
5. 🚨 **Privilege Escalation Detection** – Identify critical attack paths and escalation opportunities, including logging-based risks
6. 📈 **BloodHound Export** – Generate OpenGraph JSON with custom GCP visualizations

### **BloodHound Import**

After analysis completes:

1. Locate the generated file: `./output/gcp-bhopengraph.json`
2. Open BloodHound web interface
3. Navigate to "Data Collection" → "File Ingest"
4. Upload the JSON file
5. Explore your GCP attack surface!

---

## Enumerated Resources & Relationships

### **GCP Node Types**

GCP-Hound currently enumerates **23 distinct GCP node types** across the Google Cloud ecosystem:

| Category                  | Node Types                                               | Description                                            |
|---------------------------|---------------------------------------------------------|--------------------------------------------------------|
| **Identity & Access**     | `GCP_User`, `GCP_Group`, `GCP_ServiceAccount`, `GCP_ServiceAccountKey`, `GCP_GoogleManagedSA`,`GCP_CanSignBlob`, `GCP_CanSignJWT`  | User identities, groups, and service accounts          |
| **Organization**          | `GCP_Project`, `GCPFolder`, `GCPOrganization`                           | Organizational structure and hierarchy                 |
| **Compute & Containers**  | `GCPInstance`, `GCPCluster`, `GCPNode`                                 | Compute Engine VMs and GKE clusters                    |
| **Storage & Data**        | `GCPBucket`, `GCPDataset`, `GCPSecret`, `GCPFunction`                 | Storage, BigQuery, Secret Manager, Cloud Functions     |
| **Networking**            | `GCPNetwork`, `GCPVPC`, `GCPSubnet`, `GCPFirewall`, `GCPRole`         | Network infrastructure and roles                       |
| **Additional Services**   | `GCPPubSubTopic`, `GCPCloudFunction`, `GCPKMSKey`                     | Messaging, serverless, and encryption                  |
| **Logging & Monitoring**  | `GCPLogSink`, `GCPLogBucket`, `GCPLogMetric`                          | Logging sinks, log buckets, and log metrics            |


*Note: While `GCPPubSubTopic` is registered as a node type, **Pub/Sub enumeration is not yet implemented** in the current collectors.*


### **Attack Relationship Types**

| Edge Type | Risk Level | Description |
|-----------|------------|-------------|
| `CanCreateKeys` | **CRITICAL** | Ability to create service account keys (direct privilege escalation) |
| `CanImpersonate` | **HIGH** | Service account impersonation capabilities |
| `CanReadSecrets` and `CanReadSecretsInProject`| **HIGH** | shows which account hold privileged access to secrets |
| `CanListKeys` | **MEDIUM** | Ability to enumerate existing service account keys |
| `ContainsServiceAccount` | **LOW** | Project ownership of service accounts |
| `OwnsStorageBucket` | **MEDIUM** | Resource ownership relationships |
| `HasGoogleOwnedSA` | **INFO** | Indicates that a GCP project relies on a Google-managed service account for certain internal operations or APIs. |
| `CanModifyBucketPoliciesInProject` | **HIGH** | Indicates that an identity (user, SA) has permissions to modify storage bucket policies at the project scope, supporting privilege escalation scenarios. |
| `BelongsTo` | **INFO** | Resource-to-project associations |

### **Understanding Attack Paths**

GCP-Hound focuses on discovering privilege escalation opportunities through:

- **Service Account Key Creation** → Direct credential access → Full service account privileges
- **Cross-Project Impersonation** → Privilege escalation across GCP projects  
- **Storage Bucket Access** → Data exfiltration or modification capabilities
- **BigQuery Data Access** → Sensitive data exposure and analysis

---

## 🎨 BloodHound Visualization

### **Custom GCP Node Types**
- 🔐 **Service Accounts** – Green user-secret icon
- 📁 **Projects** – Red folder-open icon
- 🗄️ **Storage Buckets** – Blue database icon
- 📊 **BigQuery Datasets** – Purple chart-bar icon
- 👤 **Users** – Brown user-circle icon
- 🟣 **Log Sinks** – Purple stream icon
- 📨 **Log Buckets** – Teal inbox icon
- 📈 **Log Metrics** – Gold chart-line icon

### **Attack Relationship Types**
- **CanCreateKeys** - CRITICAL service account key creation
- **CanImpersonate** - HIGH-risk service account impersonation
- **CanSignBlob** - HIGH-risk, where identity (user or service account) has the `iam.serviceAccounts.signBlob` permission on service account.
- **CanSignJWT** - HIGH-risk, where `iam.serviceAccounts.signJwt` permission allows an identity to sign a JSON Web Token (JWT) using a target service account's identity
- **CanListKeys** - MEDIUM key enumeration capabilities
- **BelongsTo** - Resource ownership relationships

### **Useful BloodHound Queries**

**Show all critical attack paths:**

```
MATCH (n)-[r]->(m)
WHERE r.riskLevel = "CRITICAL"
RETURN n, r, m
```

<img width="1146" height="723" alt="image" src="https://github.com/user-attachments/assets/cd86829b-1628-4c6f-8d46-a107ecb36a0c" />

**Show complete GCP attack surface:**


```
MATCH (n:GCPResource)-[r]->(m:GCPResource)
RETURN n, r, m LIMIT 100
```

<img width="1800" height="605" alt="image" src="https://github.com/user-attachments/assets/9710a6e1-72e8-4eb0-acd7-ad33378b7643" />


#### More example queries

- Basic Node Enumeration

```
// List all service accounts
MATCH (sa:GCP_ServiceAccount) RETURN sa LIMIT 25

// List all GCP projects  
MATCH (p:GCP_Project) RETURN p LIMIT 25

// List all GCP resources
MATCH (res:GCPResource) RETURN res LIMIT 25

// Show all accounts with secret access
MATCH p = ()-[r]->()
WHERE type(r) IN ["CanReadSecrets", "CanReadSecretsInProject"]
RETURN p
LIMIT 50

// Show owner/editor secret access
MATCH p = (sa)-[r:CanReadSecretsInProject]->(proj)
WHERE r.role IN ["roles/owner", "roles/editor"]
RETURN p

// Show service account with secret access
MATCH p = (sa:GCP_ServiceAccount)-[r]->(target)
WHERE type(r) IN ["CanReadSecrets", "CanReadSecretsInProject"]
RETURN p

// Show users with secret access
MATCH p = (user:GCP_User)-[r]->(target)
WHERE type(r) IN ["CanReadSecrets", "CanReadSecretsInProject"]
RETURN p

// List all storage buckets
MATCH (b:GCPBucket) RETURN b LIMIT 25

// List all BigQuery datasets
MATCH (d:GCPDataset) RETURN d LIMIT 25

// List all log sinks
MATCH (ls:GCPLogSink) RETURN ls LIMIT 25

// List all log buckets
MATCH (lb:GCPLogBucket) RETURN lb LIMIT 25

// Find all users or service accounts with access to log sinks
MATCH (a)-[r:CanAccessLogStream|CanViewSensitiveLogs]->(ls:GCPLogSink) RETURN a, r, ls
```

- Relationship Discovery

```
// Show project-to-service-account relationships
MATCH p=(project:GCP_Project)-[r:GCP_ContainsServiceAccount]->(sa:GCP_ServiceAccount) RETURN p LIMIT 25

// Explore all service account relationships
MATCH (sa:GCP_ServiceAccount)-[r]->(target) RETURN sa, r, target LIMIT 25

// Show all GCP resource relationships
MATCH (res:GCPResource)-[r]->(target) RETURN res, r, target LIMIT 50

// Find bucket ownership relationships
MATCH p=(project:GCP_Project)-[r:OwnsStorageBucket]->(bucket:GCPBucket) RETURN p LIMIT 25
```

- Critical Security Analysis

```
// CRITICAL: Find service account key creation privileges
MATCH (source)-[r:GCP_CanCreateKeys]->(target) RETURN source, r, target

// HIGH RISK: Service account impersonation paths
MATCH (sa:GCP_ServiceAccount)-[r:GCP_CanImpersonate]->(target) RETURN sa, r, target LIMIT 25

// List key enumeration capabilities
MATCH (source)-[r:CanListKeys]->(target) RETURN source, r, target LIMIT 25

// Show all privilege escalation edges
MATCH (n)-[r]->(m) 
WHERE type(r) IN ['CanCreateKeys', 'CanImpersonate', 'CanListKeys','CanSignBlob','CanSignJWT']
RETURN n, r, m LIMIT 100
```

---

## 📈 Sample Output

```
[*] Phase 1: Authentication & Project Discovery
✅ Authenticated as: user@example-project.iam.gserviceaccount.com
✅ Discovered 1 accessible projects

[*] Phase 2: Identity Enumeration
✅ Found 7 service accounts
✅ Discovered 2 users, 1 groups

[*] Phase 3: Resource Discovery
✅ Enumerated 1 storage buckets
✅ Found 1 BigQuery datasets

[*] Phase 4: Service Account Key Access Analysis
🚨 CRITICAL: Can create keys for 7 service accounts - PRIVILEGE ESCALATION POSSIBLE

[*] Phase 5: Comprehensive Privilege Escalation Analysis
💀 CRITICAL escalation targets: 7
⚠️ HIGH-risk escalation targets: 7

[*] Phase 6: BloodHound Integration
✅ Generated OpenGraph JSON with custom GCP icons
✅ FINAL RESULT: 10 nodes, 24 edges
📁 File: ./output/gcp-bhopengraph.json
```

---

## 🔒 Security & Ethics

**⚠️ Only use on GCP environments you own or have explicit authorization to test**

---

## 🛠️ Development & Contribution

Contributions are welcome! This project is a learning exercise, and I appreciate:

- Bug reports and feature requests
- Code contributions and improvements
- Documentation enhancements
- Testing in different GCP environments

Please feel free to:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

## 🔮 Roadmap & TODO

### **Immediate Priorities**
- [ ] **Work on integrating with AD objects** - Connect GCP identities with Active Directory  
- [ ] **Work on adding more recon features and detailing** - Expand enumeration capabilities
- [ ] Expand detail level for logging privilege analysis, relationship mapping

### **Upcoming Features**
- [ ] **Pub/Sub & Messaging** - Topics, subscriptions, and Cloud Tasks enumeration
- [ ] **Advanced Serverless** - Cloud Functions, Cloud Run, and App Engine analysis
- [ ] **Enhanced Networking** - Load balancers, CDN, and interconnect discovery
---

## 🛠️ Project Structure

```
GCP-Hound/
├── bloodhound/
│   ├── __init__.py
│   └── json_builder.py
│
├── collectors/
│   ├── __init__.py
│   ├── bigquery_collector.py
│   ├── bucket_collector.py
│   ├── cloudfunctions_collector.py
│   ├── cloudsql_collector.py
│   ├── compute_collector.py
│   ├── discovery.py
│   ├── edge_builder.py
│   ├── folder_collector.py
│   ├── gke_collector.py
│   ├── iam_collector.py
│   ├── logging_collector.py 
│   ├── org_collector.py
│   ├── privesc_analyzer.py
│   ├── project_collector.py
│   ├── pubsub_collector.py
│   ├── sa_key_analyzer.py
│   ├── secret_collector.py
│   ├── service_account_collector.py
│   ├── user_collector.py
│   ├── users_groups_collector.py
│   └── util.py
│
├── utils/
|   ├── id_utils.py
│   └── auth.py
│
├── .gitignore
├── LICENSE
├── README.md
├── gcp-hound.py
├── gcp-model.json
├── register_gcp_nodes.py
└── requirements.txt
```

---

## 📞 Support & Contact

- 🐛 **Issues**: [GitHub Issues](https://github.com/F41zK4r1m/GCP-Hound/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/F41zK4r1m/GCP-Hound/discussions)

---

<div align="center">

**🎯 Enhance your GCP security posture with GCP-Hound!**

*Built as a learning project for the cybersecurity community*

</div>
