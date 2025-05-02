import React, { useState } from "react";
import { get } from "lodash";

// Helper for risk score background
const getGradient = (score) => {
  if (score === null || score === undefined) return "gray";
  const red = Math.min(255, Math.floor((score / 100) * 255));
  const green = Math.min(255, Math.floor((1 - score / 100) * 255));
  return `radial-gradient(circle, rgb(${red},${green},80), #1f2937)`;
};

const generateSummary = (module, rawData) => {
  if (!rawData) return "No summary available.";
  const error = get(rawData, "error");
  if (error) return `Error: ${error}`;

  module = module.toLowerCase();

  switch (module) {
    case "abuseipdb":
      const confidence = get(rawData.data, "abuseConfidenceScore");
      const totalReports = get(rawData.data, "totalReports");
      const countryCode = get(rawData.data, "countryCode");
      const isTor = get(rawData.data, "isTor");
      return confidence && totalReports && countryCode !== undefined
        ? `${confidence}% confidence, ${totalReports} reports, ${countryCode}, ${isTor ? "TOR user" : "Not TOR user"}`
        : "No summary available.";
    case "virustotal":
      const attributes = get(rawData, "data.attributes", {});
      const reputation = get(attributes, "reputation");
      const lastAnalysisDate = get(attributes, "last_analysis_date");
      const stats = get(attributes, "last_analysis_stats", {});
      return reputation !== undefined
        ? `Reputation: ${reputation} | Malicious: ${stats.malicious} | Suspicious: ${stats.suspicious} | Harmless: ${stats.harmless} | Last analyzed: ${new Date(lastAnalysisDate * 1000).toLocaleString()}`
        : "No summary available.";
    case "greynoise":
      const classification = get(rawData, "classification");
      return classification ? `Classification: ${classification}` : "No summary available.";
    case "shodan":
      const ip = get(rawData, "data.ip");
      const country = get(rawData, "data.country_name");
      const org = get(rawData, "data.org");
      const ports = get(rawData, "data.ports", []).length;
      const vulns = Object.keys(get(rawData, "data.vulns", {})).length;
      return ip && country && org
        ? `IP: ${ip}, Country: ${country}, Org: ${org}, Ports: ${ports}, Vulns: ${vulns}`
        : "No summary available.";
      case "urlhaus":
        const urlhausData = rawData?.[0];
        if (urlhausData) {
          const dateAdded = get(urlhausData, "dateadded");
          const status = get(urlhausData, "url_status");
          const threat = get(urlhausData, "threat");
          return `Threat: ${threat} | Status: ${status} | Date Added: ${dateAdded}`;
        }
        return "No summary available.";
    case "whois":
      const whoisData = get(rawData, "whoisData");
      if (whoisData) {
        // Use the new structure from standardize_ipwhois_info
        const { org, isp, country, city, region, country_code, asn, domain, type } = whoisData.data || {};
        
        return `
          Organization: ${org || "Unknown"} | 
          ISP: ${isp || "Unknown"} | 
          Country: ${country || "Unknown"} | 
          City: ${city || "Unknown"} | 
          Region: ${region || "Unknown"} | 
          Country Code: ${country_code || "Unknown"} | 
          ASN: ${asn || "Unknown"} | 
          Domain: ${domain || "Unknown"} | 
          Type: ${type || "Unknown"}
        `;
      }
      break;
    case "threatfox":
      const threatData = get(rawData, "data", [])[0]; // pick first match (API returns an array)
      if (threatData) {
        const confidenceLevel = get(threatData, "confidence_level");
        const threatType = get(threatData, "threat_type", "Unknown");
        const malwarePrintable = get(threatData, "malware_printable", get(threatData, "malware", "Unknown"));
        const firstSeen = get(threatData, "first_seen");
    
        return `Threat Type: ${threatType} | Malware: ${malwarePrintable} | Confidence: ${confidenceLevel}% | First Seen: ${firstSeen || "Unknown"}`;
      }
      break;
    default:
      return "No summary available.";
  }
};

const SearchResultsTable = ({ results }) => {
  const [sortBy, setSortBy] = useState("module");
  const [sortDirection, setSortDirection] = useState("asc");
  const [activeTab, setActiveTab] = useState("stats");

  const overallRiskScore = 75; // mock
  const activeModules = results.length;
  const highestRisk = Math.max(...results.map((r) => r.risk_score || 0));

  const handleSort = (column) => {
    const direction = sortBy === column && sortDirection === "asc" ? "desc" : "asc";
    setSortBy(column);
    setSortDirection(direction);
  };

  const handleDownload = (module, rawData) => {
    const jsonBlob = new Blob([JSON.stringify(rawData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(jsonBlob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${module}_data.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const sortedResults = [...results].sort((a, b) => {
    const aVal = a[sortBy];
    const bVal = b[sortBy];
    if (aVal < bVal) return sortDirection === "asc" ? -1 : 1;
    if (aVal > bVal) return sortDirection === "asc" ? 1 : -1;
    return 0;
  });


    return (
      <div className="flex justify-center mt-6 px-4">
        <div className="w-full max-w-6xl bg-gray-900 p-4 rounded-lg shadow-xl">
          {/* Tabs */}
          <div className="mb-4 border-b border-gray-700">
            <ul className="flex flex-wrap -mb-px text-sm font-medium text-center text-gray-400">
              {["stats", "details", "info"].map((tab) => (
                <li className="me-2" key={tab}>
                  <button
                    onClick={() => setActiveTab(tab)}
                    className={`inline-block p-4 border-b-2 rounded-t-lg ${
                      activeTab === tab
                        ? "text-purple-400 border-purple-400"
                        : "border-transparent hover:text-white hover:border-gray-300"
                    }`}
                  >
                    {tab === "stats" ? "Stats" : tab === "details" ? "Details" : "Indicator Info"}
                  </button>
                </li>
              ))}
            </ul>
          </div>
    
          {/* Tab Panels */}
          <div>
            {activeTab === "stats" && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 rounded-lg" style={{ background: getGradient(overallRiskScore) }}>
                  <h2 className="text-lg text-gray-200 mb-2">Overall Risk Score</h2>
                  <h1 className="text-3xl font-bold text-white">{overallRiskScore}</h1>
                </div>
                <div className="p-4 bg-gray-800 rounded-lg">
                  <h2 className="text-lg text-gray-200 mb-2">Active Modules</h2>
                  <h1 className="text-3xl font-bold text-white">{activeModules}</h1>
                </div>
                <div className="p-4 bg-gray-800 rounded-lg">
                  <h2 className="text-lg text-gray-200 mb-2">Highest Risk Score</h2>
                  <h1 className="text-3xl font-bold text-white">{highestRisk}</h1>
                </div>
              </div>
            )}
    
            {activeTab === "details" && (
              <div className="overflow-x-auto rounded-lg mt-4">
                <table className="w-full text-sm text-left text-gray-400">
                  <thead className="text-xs uppercase bg-gray-800 text-gray-400">
                    <tr>
                      <th className="px-4 py-3"></th>
                      <th
                        className="px-6 py-3 cursor-pointer hover:text-white"
                        onClick={() => handleSort("module")}
                      >
                        Module {sortBy === "module" && (sortDirection === "asc" ? "↑" : "↓")}
                      </th>
                      <th
                        className="px-6 py-3 cursor-pointer hover:text-white"
                        onClick={() => handleSort("risk_score")}
                      >
                        Risk Score {sortBy === "risk_score" && (sortDirection === "asc" ? "↑" : "↓")}
                      </th>
                      <th
                        className="px-6 py-3 cursor-pointer hover:text-white"
                        onClick={() => handleSort("summary")}
                      >
                        Summary {sortBy === "summary" && (sortDirection === "asc" ? "↑" : "↓")}
                      </th>
                      <th className="px-6 py-3">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sortedResults
                    .filter((result) => result.module !== "ipwhois")
                    .map((result, index) => {
                      const { module, risk_score, raw } = result;
                      const summary = generateSummary(module, raw);
                      const circleStyle = { background: getGradient(risk_score) };
    
                      return (
                        <tr
                          key={index}
                          className="bg-gray-900 border-b border-gray-700 hover:bg-gray-800 transition"
                        >
                          <td className="px-4 py-3">
                            <div
                              className="w-4 h-4 rounded-full"
                              style={circleStyle}
                              title={`Risk Score: ${risk_score}`}
                            ></div>
                          </td>
                          <td className="px-6 py-3 font-medium text-white">{module}</td>
                          <td className="px-6 py-3">{risk_score}</td>
                          <td className="px-6 py-3 whitespace-pre-wrap">{summary}</td>
                          <td className="px-6 py-3">
                            <button
                              onClick={() => handleDownload(module, raw)}
                              className="text-purple-400 hover:underline"
                            >
                              Download JSON
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
    
    {activeTab === "info" && (
  <div className="p-4 mt-4 bg-gray-800 rounded-lg text-gray-300">
    <h2 className="text-xl mb-2 text-purple-300">Indicator Information</h2>
    <p>This section will display WHOIS or enrichment data about the queried indicator.</p>
    {sortedResults.map((result) => {
      const { module, raw } = result;
      if (module === "ipwhois" && raw) {
        // Directly use raw to get data
        const { connection, country, city, region, country_code, type } = raw;
        const whoisData = {
          org: connection?.org || "Unknown",
          isp: connection?.isp || "Unknown",
          country: country || "Unknown",
          city: city || "Unknown",
          region: region || "Unknown",
          country_code: country_code || "Unknown",
          asn: connection?.asn || "Unknown",
          domain: connection?.domain || "Unknown",
          type: type || "Unknown",
        };
        
        return (
          <div key={result.module} className="mt-4">
            {whoisData && (
              <div>
                <p><strong>Organization:</strong> {whoisData.org}</p>
                <p><strong>ISP:</strong> {whoisData.isp}</p>
                <p><strong>Country:</strong> {whoisData.country}</p>
                <p><strong>City:</strong> {whoisData.city}</p>
                <p><strong>Region:</strong> {whoisData.region}</p>
                <p><strong>Country Code:</strong> {whoisData.country_code}</p>
                <p><strong>ASN:</strong> {whoisData.asn}</p>
                <p><strong>Domain:</strong> {whoisData.domain}</p>
                <p><strong>Type:</strong> {whoisData.type}</p>
              </div>
            )}
          </div>
        );
      }
      return null;
    })}
  </div>
)}

          </div>
        </div>
      </div>
    );
  };

export default SearchResultsTable;
