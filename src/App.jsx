import { useMemo, useState } from "react";
import "./App.css";

import {
  MapContainer,
  TileLayer,
  Marker,
  Popup,
} from "react-leaflet";

import "leaflet/dist/leaflet.css";


// ======================================================
// MAIN APP
// ======================================================

export default function App() {
  const [activePage, setActivePage] = useState("Dashboard");

  // EMAIL ANALYSIS
  const [selectedFile, setSelectedFile] = useState(null);
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [emailBody, setEmailBody] = useState("");
  const [analysisResult, setAnalysisResult] = useState(null);

  // FORENSICS
  const [rawEmailContent, setRawEmailContent] = useState("");
  const [evidenceHash, setEvidenceHash] = useState("");
  const [evidenceId, setEvidenceId] = useState("");
  const [emailDate, setEmailDate] = useState("");
  const [messageId, setMessageId] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  const [verificationMessage, setVerificationMessage] = useState("");

  // REPORTS
  const [selectedReport, setSelectedReport] = useState(null);

  // THREATS
  const [searchThreat, setSearchThreat] = useState("");
  const [threatFilter, setThreatFilter] = useState("All");
  const [selectedThreat, setSelectedThreat] = useState(null);


  // ======================================================
  // DEMO THREATS
  // ======================================================

  const threats = [
    {
      id: "TH-001",
      sender: "security-alert@unknown-example.com",
      subject: "Urgent verify your account",
      threatType: "Phishing",
      status: "Dangerous",
      risk: 100,
      location: "Unknown",
      time: "10:42 AM",
      confidence: 97,
      indicators: 7,
      links: 1,
      evidenceId: "EV-2026-839214",
      ip: "185.XX.XX.21",
      messageId: "<threat-001@example.com>",
      urlAnalysis: "1 suspicious HTTP URL detected",
      reasoning:
        "Multiple high-risk phishing indicators were detected, including urgency, account verification language, credential-related wording and a suspicious link.",
      recommendation:
        "Quarantine the email, block the sender/domain and investigate the associated URL.",
    },
    {
      id: "TH-002",
      sender: "invoice@billing-check.com",
      subject: "Unpaid invoice notification",
      threatType: "Malicious Link",
      status: "Dangerous",
      risk: 92,
      location: "Russia",
      time: "09:17 AM",
      confidence: 93,
      indicators: 6,
      links: 2,
      evidenceId: "EV-2026-742891",
      ip: "91.XX.XX.72",
      messageId: "<threat-002@example.com>",
      urlAnalysis: "2 suspicious links detected",
      reasoning:
        "The message contains payment pressure, suspicious URLs and sender characteristics commonly associated with malicious campaigns.",
      recommendation:
        "Do not open the links. Quarantine the email and investigate the sender infrastructure.",
    },
    {
      id: "TH-003",
      sender: "support@account-update.net",
      subject: "Account verification required",
      threatType: "Suspicious Sender",
      status: "Suspicious",
      risk: 67,
      location: "Germany",
      time: "Yesterday",
      confidence: 86,
      indicators: 5,
      links: 1,
      evidenceId: "EV-2026-619342",
      ip: "89.XX.XX.43",
      messageId: "<threat-003@example.com>",
      urlAnalysis: "1 potentially suspicious URL",
      reasoning:
        "The sender domain and account-verification language require additional investigation.",
      recommendation:
        "Review sender reputation and verify the request through an independent communication channel.",
    },
    {
      id: "TH-004",
      sender: "hr@company-example.com",
      subject: "Weekly meeting",
      threatType: "Normal",
      status: "Safe",
      risk: 8,
      location: "India",
      time: "Yesterday",
      confidence: 94,
      indicators: 0,
      links: 0,
      evidenceId: "EV-2026-518234",
      ip: "103.XX.XX.12",
      messageId: "<threat-004@example.com>",
      urlAnalysis: "No suspicious URLs detected",
      reasoning:
        "No significant phishing or malicious indicators were detected in the email.",
      recommendation:
        "No immediate action required.",
    },
    {
      id: "TH-005",
      sender: "delivery@parcel-notice.net",
      subject: "Package delivery issue",
      threatType: "Phishing",
      status: "Suspicious",
      risk: 74,
      location: "United States",
      time: "2 days ago",
      confidence: 86,
      indicators: 6,
      links: 1,
      evidenceId: "EV-2026-437821",
      ip: "172.XX.XX.54",
      messageId: "<threat-005@example.com>",
      urlAnalysis: "1 suspicious tracking URL",
      reasoning:
        "The email uses delivery-related urgency and contains a suspicious tracking link.",
      recommendation:
        "Verify the delivery independently before interacting with the message.",
    },
    {
      id: "TH-006",
      sender: "newsletter@trusted-company.com",
      subject: "Security newsletter",
      threatType: "Normal",
      status: "Safe",
      risk: 4,
      location: "India",
      time: "3 days ago",
      confidence: 94,
      indicators: 0,
      links: 0,
      evidenceId: "EV-2026-321674",
      ip: "103.XX.XX.44",
      messageId: "<threat-006@example.com>",
      urlAnalysis: "No suspicious URLs detected",
      reasoning:
        "The sender and content appear consistent with a legitimate newsletter.",
      recommendation:
        "No immediate action required.",
    },
  ];


  // ======================================================
  // SHA-256
  // ======================================================

  async function generateSHA256(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);

    const hashBuffer = await crypto.subtle.digest(
      "SHA-256",
      data
    );

    return Array.from(new Uint8Array(hashBuffer))
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
  }


  // ======================================================
  // EMAIL UPLOAD
  // ======================================================

  const handleFileUpload = (event) => {
    const file = event.target.files?.[0];

    if (!file) return;

    setSelectedFile(file);
    setVerificationMessage("");

    const reader = new FileReader();

    reader.onload = async (e) => {
      const content = e.target.result || "";

      setRawEmailContent(content);

      const fromMatch = content.match(
        /^From:\s*(.+)$/im
      );

      const subjectMatch = content.match(
        /^Subject:\s*(.+)$/im
      );

      const dateMatch = content.match(
        /^Date:\s*(.+)$/im
      );

      const messageIdMatch = content.match(
        /^Message-ID:\s*(.+)$/im
      );

      const ipMatch =
        content.match(
          /^X-Originating-IP:\s*\[?([0-9.]+)\]?/im
        ) ||
        content.match(
          /Received:.*?(\d{1,3}(?:\.\d{1,3}){3})/im
        );

      const from = fromMatch
        ? fromMatch[1].trim()
        : "Unknown sender";

      const emailSubject = subjectMatch
        ? subjectMatch[1].trim()
        : "No subject";

      const date = dateMatch
        ? dateMatch[1].trim()
        : "Unknown";

      const msgId = messageIdMatch
        ? messageIdMatch[1].trim()
        : "Not available";

      const ip = ipMatch
        ? ipMatch[1]
        : "Not available";

      const bodyStart = content.search(
        /\r?\n\r?\n/
      );

      const body =
        bodyStart >= 0
          ? content.slice(bodyStart + 2)
          : content;

      setSender(from);
      setSubject(emailSubject);
      setEmailDate(date);
      setMessageId(msgId);
      setSourceIp(ip);
      setEmailBody(body);

      const hash = await generateSHA256(content);

      setEvidenceHash(hash);

      setEvidenceId(
        `EV-${new Date().getFullYear()}-${Date.now()
          .toString()
          .slice(-6)}`
      );

      setAnalysisResult(null);
    };

    reader.readAsText(file);
  };


  // ======================================================
  // EMAIL ANALYSIS
  // ======================================================

  const analyzeEmail = () => {
    const text =
      `${sender} ${subject} ${emailBody}`.toLowerCase();

    const suspiciousWords = [
      "urgent",
      "password",
      "verify",
      "account suspended",
      "click",
      "otp",
      "immediately",
      "confirm",
    ];

    const detectedIndicators =
      suspiciousWords.filter((word) =>
        text.includes(word)
      );

    const indicators =
      detectedIndicators.length;

    const hasSuspiciousLink =
      text.includes("http://") ||
      text.includes("https://");

    let riskScore =
      indicators * 11 +
      (hasSuspiciousLink ? 25 : 0);

    if (riskScore > 100) {
      riskScore = 100;
    }

    let status;
    let threatType;
    let senderStatus;
    let confidence;
    let reasoning;
    let recommendedAction;

    if (riskScore >= 70) {
      status = "Dangerous";
      threatType = "Phishing";
      senderStatus = "Suspicious";
      confidence = 97;

      reasoning =
        "Multiple high-risk phishing indicators were detected, including urgency, account verification language, credential-related wording and a suspicious link.";

      recommendedAction =
        "Quarantine the email, block the sender/domain and investigate the associated URL.";
    } else if (riskScore >= 35) {
      status = "Suspicious";
      threatType = "Potential Phishing";
      senderStatus = "Unknown";
      confidence = 86;

      reasoning =
        "Several suspicious characteristics were detected. Further investigation of the sender and message content is recommended.";

      recommendedAction =
        "Verify the sender independently and investigate suspicious links before taking action.";
    } else {
      status = "Safe";
      threatType = "Normal";
      senderStatus = "Trusted";
      confidence = 94;

      reasoning =
        "No significant phishing or malicious indicators were detected in the analyzed email.";

      recommendedAction =
        "No immediate action required.";
    }

    const urlAnalysis = hasSuspiciousLink
      ? "Suspicious HTTP/HTTPS URL detected in message content."
      : "No suspicious URLs detected.";

    setAnalysisResult({
      riskScore,
      status,
      threatType,
      senderStatus,
      suspiciousLinks: hasSuspiciousLink ? 1 : 0,
      indicators,
      confidence,
      detectedIndicators,
      reasoning,
      recommendedAction,
      urlAnalysis,
    });
  };


  // ======================================================
  // VERIFY FORENSIC HASH
  // ======================================================

  const verifyEvidence = async () => {
    if (!rawEmailContent || !evidenceHash) {
      setVerificationMessage(
        "No evidence available for verification."
      );
      return;
    }

    const currentHash =
      await generateSHA256(rawEmailContent);

    if (currentHash === evidenceHash) {
      setVerificationMessage(
        "✓ Integrity verified — SHA-256 hash matches the original evidence."
      );
    } else {
      setVerificationMessage(
        "⚠ Integrity verification failed — evidence has changed."
      );
    }
  };


  // ======================================================
  // REPORT DOWNLOAD
  // ======================================================

  const downloadReport = (report) => {
    const text = `
CYBERINTEL FORENSIC INVESTIGATION REPORT
SIH26106 — AI-Powered Email Threat Detection,
GeoLocation and Forensic Intelligence Platform

==================================================

EVIDENCE INFORMATION

Evidence ID: ${report.evidenceId}
File: ${report.fileName}
SHA-256: ${report.hash}

==================================================

EMAIL INFORMATION

Sender: ${report.sender}
Subject: ${report.subject}
Date: ${report.date}
Message ID: ${report.messageId}
Source IP: ${report.sourceIp}

==================================================

THREAT ANALYSIS

Risk Score: ${report.riskScore}/100
Classification: ${report.status}
Threat Type: ${report.threatType}
Sender Status: ${report.senderStatus}
Suspicious Links: ${report.suspiciousLinks}
Threat Indicators: ${report.indicators}
AI Confidence: ${report.confidence}%

URL Analysis:
${report.urlAnalysis}

==================================================

AI ASSESSMENT

${report.reasoning}

==================================================

RECOMMENDED ACTION

${report.recommendedAction}

==================================================

INTEGRITY

SHA-256:
${report.hash}

Evidence integrity can be independently verified by
recalculating the SHA-256 hash of the original email.

==================================================

DISCLAIMER

This report is generated for cybersecurity investigation
and demonstration purposes. Final incident decisions
should be made by a qualified security analyst.

==================================================
`;

    const blob = new Blob(
      [text],
      { type: "text/plain" }
    );

    const url =
      URL.createObjectURL(blob);

    const link =
      document.createElement("a");

    link.href = url;
    link.download =
      `${report.evidenceId}-forensic-report.txt`;

    link.click();

    URL.revokeObjectURL(url);
  };


  // ======================================================
  // FILTER THREATS
  // ======================================================

  const filteredThreats = useMemo(() => {
    return threats.filter((threat) => {
      const matchesSearch =
        threat.sender
          .toLowerCase()
          .includes(searchThreat.toLowerCase()) ||
        threat.subject
          .toLowerCase()
          .includes(searchThreat.toLowerCase()) ||
        threat.threatType
          .toLowerCase()
          .includes(searchThreat.toLowerCase());

      const matchesFilter =
        threatFilter === "All" ||
        threat.status === threatFilter;

      return matchesSearch && matchesFilter;
    });
  }, [searchThreat, threatFilter]);


  // ======================================================
  // SIDEBAR
  // ======================================================

  const menuItems = [
    "Dashboard",
    "Email Analysis",
    "Threats",
    "Geo Intelligence",
    "Forensics",
    "Reports",
  ];


  return (
    <div className="app">

      <aside className="sidebar">

        <div className="brand">
          <h1>CyberIntel</h1>
          <p>SIH26106 • Email Threat Intelligence</p>
        </div>

        <nav>
          {menuItems.map((item) => (
            <button
              key={item}
              className={
                activePage === item
                  ? "nav-item active"
                  : "nav-item"
              }
              onClick={() => {
                setActivePage(item);
                setSelectedThreat(null);
                setSelectedReport(null);
              }}
            >
              {item}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="system-status">
            <span className="status-dot"></span>
            System Online
          </div>

          <p>AI Security Analyst Platform</p>
        </div>

      </aside>


      <main className="main">

        {/* ==================================================
            DASHBOARD
        ================================================== */}

        {activePage === "Dashboard" && (
          <Dashboard
            threats={threats}
            onThreatClick={(threat) => {
              setSelectedThreat(threat);
              setActivePage("Threats");
            }}
          />
        )}


        {/* ==================================================
            EMAIL ANALYSIS
        ================================================== */}

        {activePage === "Email Analysis" && (
          <EmailAnalysis
  selectedFile={selectedFile}
  sender={sender}
  subject={subject}
  emailDate={emailDate}
  emailBody={emailBody}
            analysisResult={analysisResult}
            handleFileUpload={handleFileUpload}
            analyzeEmail={analyzeEmail}
          />
        )}


        {/* ==================================================
            THREATS
        ================================================== */}

        {activePage === "Threats" && (
          <Threats
            threats={filteredThreats}
            searchThreat={searchThreat}
            setSearchThreat={setSearchThreat}
            threatFilter={threatFilter}
            setThreatFilter={setThreatFilter}
            selectedThreat={selectedThreat}
            setSelectedThreat={setSelectedThreat}
          />
        )}


        {/* ==================================================
            GEO INTELLIGENCE
        ================================================== */}

        {activePage === "Geo Intelligence" && (
          <GeoIntelligence />
        )}


        {/* ==================================================
            FORENSICS
        ================================================== */}

        {activePage === "Forensics" && (
          <Forensics
            selectedFile={selectedFile}
            sender={sender}
            subject={subject}
            emailDate={emailDate}
            messageId={messageId}
            sourceIp={sourceIp}
            evidenceId={evidenceId}
            evidenceHash={evidenceHash}
            verificationMessage={verificationMessage}
            rawEmailContent={rawEmailContent}
            handleFileUpload={handleFileUpload}
            verifyEvidence={verifyEvidence}
          />
        )}


        {/* ==================================================
            REPORTS
        ================================================== */}

        {activePage === "Reports" && (
          <Reports
            selectedReport={selectedReport}
            setSelectedReport={setSelectedReport}
            selectedFile={selectedFile}
            sender={sender}
            subject={subject}
            emailDate={emailDate}
            messageId={messageId}
            sourceIp={sourceIp}
            evidenceId={evidenceId}
            evidenceHash={evidenceHash}
            analysisResult={analysisResult}
            downloadReport={downloadReport}
          />
        )}

      </main>

    </div>
  );
}


// ======================================================
// DASHBOARD
// ======================================================

function Dashboard({ threats, onThreatClick }) {

  const recentThreats =
    threats.slice(0, 4);

  return (
    <div>

      <PageHeader
        title="Security Dashboard"
        subtitle="AI-powered email threat detection and forensic intelligence"
      />

      <div className="stats-grid">

        <StatCard
          title="Emails Scanned"
          value="1,284"
          label="Total analyzed"
        />

        <StatCard
          title="Threats Detected"
          value="48"
          label="Potential threats"
        />

        <StatCard
          title="Dangerous"
          value="17"
          label="High-risk emails"
        />

        <StatCard
          title="Safe"
          value="1,236"
          label="No threat detected"
        />

      </div>


      <div className="dashboard-grid">

        <section className="panel">

          <div className="panel-header">
            <div>
              <h2>Threat Activity</h2>
              <p>Threats detected over the last 7 days</p>
            </div>
          </div>

          <div className="bar-chart">

            {[
              ["Mon", 18],
              ["Tue", 27],
              ["Wed", 21],
              ["Thu", 35],
              ["Fri", 31],
              ["Sat", 42],
              ["Sun", 28],
            ].map(([day, value]) => (
              <div
                className="bar-column"
                key={day}
              >
                <div
                  className="bar"
                  style={{
                    height: `${value * 5}px`,
                  }}
                ></div>

                <span>{day}</span>
              </div>
            ))}

          </div>

        </section>


        <section className="panel">

          <div className="panel-header">
            <div>
              <h2>Threat Distribution</h2>
              <p>Classification breakdown</p>
            </div>
          </div>

          <div className="donut-area">

            <div className="donut">
              <div className="donut-center">
                <strong>48</strong>
                <span>Threats</span>
              </div>
            </div>

            <div className="donut-legend">

              <LegendItem
                label="Phishing"
                value="46%"
              />

              <LegendItem
                label="Malicious Links"
                value="29%"
              />

              <LegendItem
                label="Spoofing"
                value="16%"
              />

              <LegendItem
                label="Other"
                value="9%"
              />

            </div>

          </div>

        </section>

      </div>


      <div className="dashboard-grid">

        <section className="panel">

          <div className="panel-header">
            <div>
              <h2>Recent Threat Activity</h2>
              <p>Latest analyzed emails</p>
            </div>

            <button
              className="text-button"
              onClick={() => onThreatClick(threats[0])}
            >
              View all
            </button>
          </div>

          <div className="activity-list">

            {recentThreats.map((threat) => (
              <button
                className="activity-row"
                key={threat.id}
                onClick={() =>
                  onThreatClick(threat)
                }
              >

                <div className="activity-main">
                  <strong>
                    {threat.subject}
                  </strong>

                  <span>
                    {threat.sender}
                  </span>
                </div>

                <StatusBadge
                  status={threat.status}
                />

                <strong>
                  {threat.risk}
                </strong>

              </button>
            ))}

          </div>

        </section>


        <section className="panel">

          <div className="panel-header">
            <div>
              <h2>Top Threat Locations</h2>
              <p>Detected sender locations</p>
            </div>
          </div>

          <LocationBar
            name="India"
            value={18}
            max={18}
          />

          <LocationBar
            name="United States"
            value={11}
            max={18}
          />

          <LocationBar
            name="Russia"
            value={8}
            max={18}
          />

          <LocationBar
            name="Germany"
            value={6}
            max={18}
          />

        </section>

      </div>

    </div>
  );
}


// ======================================================
// EMAIL ANALYSIS
// ======================================================

function EmailAnalysis({
  selectedFile,
  sender,
  subject,
  emailDate,
  emailBody,
  analysisResult,
  handleFileUpload,
  analyzeEmail,
}) {

  return (
    <div>

      <PageHeader
        title="Email Analysis"
        subtitle="Upload and analyze suspicious email evidence"
      />

      <section className="panel">

        <h2>Upload Email Evidence</h2>

        <p className="muted">
          Upload a raw <strong>.eml</strong> email file
          for AI-powered threat analysis.
        </p>

        <div className="upload-box">

          <input
            type="file"
            accept=".eml"
            onChange={handleFileUpload}
          />

          {selectedFile && (
            <div className="file-selected">
              ✓ File selected: {selectedFile.name}
            </div>
          )}

        </div>

      </section>


      {selectedFile && (
        <section className="panel">

          <div className="panel-header">

            <div>
              <h2>Email Information</h2>
              <p>Extracted from uploaded evidence</p>
            </div>

            <button
              className="primary-button"
              onClick={analyzeEmail}
            >
              Analyze Email
            </button>

          </div>


          <div className="email-info-grid">

            <InfoBox
              label="Sender"
              value={sender}
            />

            <InfoBox
              label="Subject"
              value={subject}
            />

            <InfoBox
              label="Date"
              value={emailDate}
            />

          </div>


          <div className="email-body">

            <h3>Email Content</h3>

            <pre>
              {emailBody || "No email body detected."}
            </pre>

          </div>

        </section>
      )}


      {analysisResult && (
        <AnalysisResult
          result={analysisResult}
        />
      )}

    </div>
  );
}


// ======================================================
// ANALYSIS RESULT
// ======================================================

function AnalysisResult({ result }) {

  return (
    <section className="panel">

      <div className="panel-header">

        <div>
          <h2>AI Threat Analysis</h2>
          <p>
            Automated cybersecurity assessment
          </p>
        </div>

        <StatusBadge
          status={result.status}
        />

      </div>


      <div className="risk-section">

        <div
          className={`risk-circle ${
            result.status.toLowerCase()
          }`}
        >
          <strong>
            {result.riskScore}
          </strong>

          <span>
            Risk Score
          </span>
        </div>


        <div className="analysis-summary">

          <AnalysisItem
            label="Classification"
            value={result.threatType}
          />

          <AnalysisItem
            label="Sender Status"
            value={result.senderStatus}
          />

          <AnalysisItem
            label="AI Confidence"
            value={`${result.confidence}%`}
          />

          <AnalysisItem
            label="Suspicious Links"
            value={
              `${result.suspiciousLinks} Detected`
            }
          />

          <AnalysisItem
            label="Threat Indicators"
            value={
              `${result.indicators} Detected`
            }
          />

        </div>

      </div>


      <div className="analysis-detail-grid">

        <div className="detail-card">

          <h3>AI Reasoning</h3>

          <p>
            {result.reasoning}
          </p>

        </div>


        <div className="detail-card">

          <h3>Detected Indicators</h3>

          {result.detectedIndicators.length > 0 ? (
            <div className="tag-list">

              {result.detectedIndicators.map(
                (indicator) => (
                  <span
                    className="indicator-tag"
                    key={indicator}
                  >
                    {indicator}
                  </span>
                )
              )}

            </div>
          ) : (
            <p className="muted">
              No suspicious indicators detected.
            </p>
          )}

        </div>


        <div className="detail-card">

          <h3>URL Analysis</h3>

          <p>
            {result.urlAnalysis}
          </p>

        </div>


        <div className="detail-card recommendation">

          <h3>Analyst Recommendation</h3>

          <p>
            {result.recommendedAction}
          </p>

        </div>

      </div>

    </section>
  );
}


// ======================================================
// THREATS
// ======================================================

function Threats({
  threats,
  searchThreat,
  setSearchThreat,
  threatFilter,
  setThreatFilter,
  selectedThreat,
  setSelectedThreat,
}) {

  if (selectedThreat) {
    return (
      <ThreatInvestigation
        threat={selectedThreat}
        onBack={() =>
          setSelectedThreat(null)
        }
      />
    );
  }


  return (
    <div>

      <PageHeader
        title="Threat Intelligence"
        subtitle="Investigate detected email threats and security indicators"
      />


      <section className="panel">

        <div className="threat-toolbar">

          <input
            className="search-input"
            placeholder="Search sender, subject or threat..."
            value={searchThreat}
            onChange={(e) =>
              setSearchThreat(e.target.value)
            }
          />

          <select
            value={threatFilter}
            onChange={(e) =>
              setThreatFilter(e.target.value)
            }
          >
            <option>All</option>
            <option>Dangerous</option>
            <option>Suspicious</option>
            <option>Safe</option>
          </select>

        </div>


        <div className="threat-table">

          <div className="threat-table-head">
            <span>Sender</span>
            <span>Subject</span>
            <span>Threat Type</span>
            <span>Status</span>
            <span>Risk</span>
            <span>Location</span>
            <span></span>
          </div>


          {threats.map((threat) => (

            <div
              className="threat-table-row"
              key={threat.id}
            >

              <span>
                {threat.sender}
              </span>

              <span>
                {threat.subject}
              </span>

              <span>
                {threat.threatType}
              </span>

              <StatusBadge
                status={threat.status}
              />

              <strong>
                {threat.risk}
              </strong>

              <span>
                {threat.location}
              </span>

              <button
                className="investigate-button"
                onClick={() =>
                  setSelectedThreat(threat)
                }
              >
                Investigate
              </button>

            </div>

          ))}

        </div>

      </section>

    </div>
  );
}


// ======================================================
// THREAT INVESTIGATION
// ======================================================

function ThreatInvestigation({
  threat,
  onBack,
}) {

  return (
    <div>

      <button
        className="back-button"
        onClick={onBack}
      >
        ← Back to Threats
      </button>


      <PageHeader
        title="Threat Investigation"
        subtitle={`Investigation ${threat.id}`}
      />


      <div className="investigation-top">

        <div className="panel">

          <div className="investigation-header">

            <div>

              <span className="small-label">
                THREAT ID
              </span>

              <h2>{threat.id}</h2>

              <p>
                {threat.subject}
              </p>

            </div>

            <StatusBadge
              status={threat.status}
            />

          </div>

        </div>


        <div className="panel investigation-risk">

          <span className="small-label">
            RISK SCORE
          </span>

          <div className="big-risk">
            {threat.risk}
            <small>/100</small>
          </div>

          <div className="risk-progress">
            <div
              style={{
                width: `${threat.risk}%`,
              }}
            ></div>
          </div>

        </div>

      </div>


      <div className="info-grid">

        <InfoBox
          label="Sender"
          value={threat.sender}
        />

        <InfoBox
          label="Threat Type"
          value={threat.threatType}
        />

        <InfoBox
          label="AI Confidence"
          value={`${threat.confidence}%`}
        />

        <InfoBox
          label="Sender Location"
          value={threat.location}
        />

        <InfoBox
          label="Source IP"
          value={threat.ip}
        />

        <InfoBox
          label="Evidence ID"
          value={threat.evidenceId}
        />

      </div>


      <div className="investigation-grid">

        <section className="panel">

          <h2>AI Threat Assessment</h2>

          <div className="assessment-row">

            <span>Classification</span>

            <strong>
              {threat.threatType}
            </strong>

          </div>

          <div className="assessment-row">

            <span>AI Confidence</span>

            <strong>
              {threat.confidence}%
            </strong>

          </div>

          <div className="assessment-row">

            <span>Threat Indicators</span>

            <strong>
              {threat.indicators}
            </strong>

          </div>

          <div className="assessment-row">

            <span>Suspicious Links</span>

            <strong>
              {threat.links}
            </strong>

          </div>

          <div className="assessment-row">

            <span>Detection Time</span>

            <strong>
              {threat.time}
            </strong>

          </div>

        </section>


        <section className="panel">

          <h2>Threat Indicators</h2>

          <div className="indicator-large-grid">

            <div className="indicator-large">
              <strong>
                {threat.indicators}
              </strong>
              <span>
                Indicators Detected
              </span>
            </div>

            <div className="indicator-large">
              <strong>
                {threat.links}
              </strong>
              <span>
                Suspicious Links
              </span>
            </div>

            <div className="indicator-large">
              <strong>
                {threat.confidence}%
              </strong>
              <span>
                AI Confidence
              </span>
            </div>

          </div>

        </section>

      </div>


      <div className="investigation-grid">

        <section className="panel">

          <h2>URL Threat Analysis</h2>

          <div className="url-analysis-box">
            {threat.urlAnalysis}
          </div>

          <p className="muted">
            URLs should be investigated before
            opening or allowing access.
          </p>

        </section>


        <section className="panel">

          <h2>AI Reasoning</h2>

          <p className="large-description">
            {threat.reasoning}
          </p>

        </section>

      </div>


      <section className="panel">

        <h2>Forensic Evidence</h2>

        <div className="forensic-grid">

          <InfoBox
            label="Evidence ID"
            value={threat.evidenceId}
          />

          <InfoBox
            label="Message ID"
            value={threat.messageId}
          />

          <InfoBox
            label="Source IP"
            value={threat.ip}
          />

          <div className="hash-box">

            <span className="small-label">
              SHA-256 INTEGRITY
            </span>

            <strong>
              SHA-256 Hash Recorded
            </strong>

            <span className="verified">
              ✓ Evidence integrity available
            </span>

          </div>

        </div>

      </section>


      <section className="panel recommendation-panel">

        <h2>Analyst Recommendation</h2>

        <p>
          {threat.recommendation}
        </p>

      </section>

    </div>
  );
}


// ======================================================
// GEO INTELLIGENCE
// ======================================================

function GeoIntelligence() {

  const locations = [
    {
      name: "India",
      position: [20.5937, 78.9629],
      threats: 18,
      status: "Safe",
    },
    {
      name: "Russia",
      position: [61.524, 105.3188],
      threats: 8,
      status: "Dangerous",
    },
    {
      name: "United States",
      position: [37.0902, -95.7129],
      threats: 11,
      status: "Suspicious",
    },
    {
      name: "Germany",
      position: [51.1657, 10.4515],
      threats: 6,
      status: "Suspicious",
    },
    {
      name: "United Kingdom",
      position: [55.3781, -3.436],
      threats: 5,
      status: "Safe",
    },
  ];


  return (
    <div>

      <PageHeader
        title="Geo Intelligence"
        subtitle="Geographic visualization of email threat sources"
      />


      <section className="panel">

        <div className="panel-header">

          <div>
            <h2>Threat Source Map</h2>
            <p>
              Interactive geographic intelligence
            </p>
          </div>

        </div>


        <div className="threat-map">

          <MapContainer
            center={[25, 20]}
            zoom={2}
            scrollWheelZoom={true}
          >

            <TileLayer
              attribution='&copy; OpenStreetMap contributors'
              url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            />


            {locations.map((location) => (

              <Marker
                key={location.name}
                position={location.position}
              >

                <Popup>

                  <strong>
                    {location.name}
                  </strong>

                  <br />

                  Threats detected:
                  {" "}
                  {location.threats}

                  <br />

                  Status:
                  {" "}
                  {location.status}

                </Popup>

              </Marker>

            ))}

          </MapContainer>

        </div>


        <div className="map-legend">

          <div className="legend-item">
            <span className="legend-dot dangerous"></span>
            Dangerous
          </div>

          <div className="legend-item">
            <span className="legend-dot suspicious"></span>
            Suspicious
          </div>

          <div className="legend-item">
            <span className="legend-dot safe"></span>
            Safe
          </div>

        </div>

      </section>

    </div>
  );
}


// ======================================================
// FORENSICS
// ======================================================

function Forensics({
  selectedFile,
  sender,
  subject,
  emailDate,
  messageId,
  sourceIp,
  evidenceId,
  evidenceHash,
  verificationMessage,
  handleFileUpload,
  verifyEvidence,
}) {

  return (
    <div>

      <PageHeader
        title="Forensic Intelligence"
        subtitle="Evidence preservation, metadata and integrity verification"
      />


      <section className="panel">

        <h2>Evidence Upload</h2>

        <div className="upload-box">

          <input
            type="file"
            accept=".eml"
            onChange={handleFileUpload}
          />

          {selectedFile && (
            <div className="file-selected">
              ✓ {selectedFile.name}
            </div>
          )}

        </div>

      </section>


      {selectedFile && (

        <>

          <section className="panel">

            <div className="panel-header">

              <div>
                <h2>Evidence Metadata</h2>
                <p>
                  Extracted email forensic information
                </p>
              </div>

              <span className="integrity-badge">
                Evidence Preserved
              </span>

            </div>


            <div className="forensic-grid">

              <InfoBox
                label="Evidence ID"
                value={evidenceId}
              />

              <InfoBox
                label="File Name"
                value={selectedFile.name}
              />

              <InfoBox
                label="Sender"
                value={sender}
              />

              <InfoBox
                label="Subject"
                value={subject}
              />

              <InfoBox
                label="Date"
                value={emailDate}
              />

              <InfoBox
                label="Message ID"
                value={messageId}
              />

              <InfoBox
                label="Source IP"
                value={sourceIp}
              />

            </div>

          </section>


          <section className="panel">

            <h2>Investigation Assessment</h2>
            <p className="large-description">
              The uploaded evidence has been preserved and analyzed.
              The detected indicators and suspicious URL are consistent
              with a high-risk phishing attempt.
            </p>
          </section>


          <section className="panel">

            <h2>SHA-256 Evidence Integrity</h2>

            <div className="hash-container">

              <span className="small-label">
                SHA-256 HASH
              </span>

              <code>
                {evidenceHash}
              </code>

            </div>


            <button
              className="primary-button"
              onClick={verifyEvidence}
            >
              Verify Integrity
            </button>


            {verificationMessage && (
              <div className="verification-message">
                {verificationMessage}
              </div>
            )}

          </section>

        </>

      )}

    </div>
  );
}


// ======================================================
// REPORTS
// ======================================================

function Reports({
  selectedReport,
  setSelectedReport,
  selectedFile,
  sender,
  subject,
  emailDate,
  messageId,
  sourceIp,
  evidenceId,
  evidenceHash,
  analysisResult,
  downloadReport,
}) {

  const reportReady =
    selectedFile &&
    analysisResult &&
    evidenceHash;


  if (selectedReport) {

    return (
      <div>

        <button
          className="back-button"
          onClick={() =>
            setSelectedReport(null)
          }
        >
          ← Back to Reports
        </button>


        <PageHeader
          title="Investigation Report"
          subtitle={selectedReport.evidenceId}
        />


        <section className="panel">

          <div className="panel-header">

            <div>
              <h2>
                Forensic Investigation Report
              </h2>

              <p>
                SIH26106 CyberIntel Platform
              </p>
            </div>

            <button
              className="primary-button"
              onClick={() =>
                downloadReport(selectedReport)
              }
            >
              Download Report
            </button>

          </div>


          <div className="report-section">

            <h3>Evidence Information</h3>

            <div className="forensic-grid">

              <InfoBox
                label="Evidence ID"
                value={selectedReport.evidenceId}
              />

              <InfoBox
                label="File"
                value={selectedReport.fileName}
              />

              <InfoBox
                label="SHA-256"
                value={selectedReport.hash}
              />

            </div>

          </div>


          <div className="report-section">

            <h3>Email Information</h3>

            <div className="forensic-grid">

              <InfoBox
                label="Sender"
                value={selectedReport.sender}
              />

              <InfoBox
                label="Subject"
                value={selectedReport.subject}
              />

              <InfoBox
                label="Date"
                value={selectedReport.date}
              />

              <InfoBox
                label="Message ID"
                value={selectedReport.messageId}
              />

              <InfoBox
                label="Source IP"
                value={selectedReport.sourceIp}
              />

            </div>

          </div>


          <div className="report-section">

            <h3>Threat Analysis</h3>

            <div className="forensic-grid">

              <InfoBox
                label="Risk Score"
                value={`${selectedReport.riskScore}/100`}
              />

              <InfoBox
                label="Classification"
                value={selectedReport.status}
              />

              <InfoBox
                label="Threat Type"
                value={selectedReport.threatType}
              />

              <InfoBox
                label="AI Confidence"
                value={`${selectedReport.confidence}%`}
              />

              <InfoBox
                label="Suspicious Links"
                value={selectedReport.suspiciousLinks}
              />

              <InfoBox
                label="Threat Indicators"
                value={selectedReport.indicators}
              />

            </div>

          </div>


          <div className="report-section">

            <h3>AI Assessment</h3>

            <p>
              {selectedReport.reasoning}
            </p>

          </div>


          <div className="report-section">

            <h3>Recommended Action</h3>

            <p>
              {selectedReport.recommendedAction}
            </p>

          </div>

        </section>

      </div>
    );
  }


  return (
    <div>

      <PageHeader
        title="Forensic Reports"
        subtitle="Generate and review investigation reports"
      />


      <section className="panel">

        <div className="panel-header">

          <div>
            <h2>Current Investigation</h2>
            <p>
              Generate a report from the analyzed evidence
            </p>
          </div>

          {reportReady && (
            <span className="integrity-badge">
              Ready
            </span>
          )}

        </div>


        {!reportReady ? (

          <div className="empty-state">

            <h3>
              No completed investigation
            </h3>

            <p>
              Upload and analyze an email from the
              Email Analysis page before generating
              a forensic report.
            </p>

          </div>

        ) : (

          <div className="report-card">

            <div>

              <span className="small-label">
                EVIDENCE ID
              </span>

              <h3>
                {evidenceId}
              </h3>

              <p>
                {selectedFile.name}
              </p>

            </div>


            <button
              className="primary-button"
              onClick={() => {

                const report = {
                  evidenceId,
                  fileName: selectedFile.name,
                  sender,
                  subject,
                  date: emailDate,
                  messageId,
                  sourceIp,
                  hash: evidenceHash,
                  riskScore:
                    analysisResult.riskScore,
                  status:
                    analysisResult.status,
                  threatType:
                    analysisResult.threatType,
                  senderStatus:
                    analysisResult.senderStatus,
                  suspiciousLinks:
                    analysisResult.suspiciousLinks,
                  indicators:
                    analysisResult.indicators,
                  confidence:
                    analysisResult.confidence,
                  reasoning:
                    analysisResult.reasoning,
                  recommendedAction:
                    analysisResult.recommendedAction,
                  urlAnalysis:
                    analysisResult.urlAnalysis,
                };

                setSelectedReport(report);

              }}
            >
              View Investigation Report
            </button>

          </div>

        )}

      </section>

    </div>
  );
}


// ======================================================
// SMALL COMPONENTS
// ======================================================

function PageHeader({
  title,
  subtitle,
}) {

  return (
    <header className="page-header">

      <div>

        <h1>{title}</h1>

        <p>{subtitle}</p>

      </div>

      <div className="header-badge">
        SIH26106
      </div>

    </header>
  );
}


function StatCard({
  title,
  value,
  label,
}) {

  return (
    <div className="stat-card">

      <span>{title}</span>

      <strong>{value}</strong>

      <small>{label}</small>

    </div>
  );
}


function StatusBadge({
  status,
}) {

  return (
    <span
      className={`status-badge ${status.toLowerCase()}`}
    >
      {status}
    </span>
  );
}


function InfoBox({
  label,
  value,
}) {

  return (
    <div className="info-box">

      <span className="small-label">
        {label}
      </span>

      <strong>
        {value || "Not available"}
      </strong>

    </div>
  );
}


function AnalysisItem({
  label,
  value,
}) {

  return (
    <div className="analysis-item">

      <span>{label}</span>

      <strong>{value}</strong>

    </div>
  );
}


function LegendItem({
  label,
  value,
}) {

  return (
    <div className="legend-line">

      <span>{label}</span>

      <strong>{value}</strong>

    </div>
  );
}


function LocationBar({
  name,
  value,
  max,
}) {

  return (
    <div className="location-row">

      <div className="location-label">

        <span>{name}</span>

        <strong>{value}</strong>

      </div>

      <div className="location-track">

        <div
          className="location-fill"
          style={{
            width: `${(value / max) * 100}%`,
          }}
        ></div>

      </div>

    </div>
  );
}