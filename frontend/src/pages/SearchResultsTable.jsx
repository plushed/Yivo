import React, { useState } from "react";

// Function to generate a brief summary for each module
const generateSummary = (module, data) => {
  switch (module) {
    case "AbuseIPDB":
      const abuseIPDBData = data.raw?.data || {};  // Safely access raw.data
      return `${abuseIPDBData.abuseConfidenceScore ?? "?"}% confidence, 
              ${abuseIPDBData.totalReports ?? "?"} reports, 
              ${abuseIPDBData.countryCode ?? "?"}`;
              
    case "VirusTotal":
      return `${data.malicious ?? "?"} malicious, ${data.suspicious ?? "?"} suspicious, reputation ${data.reputation ?? "?"}`;
    
    // Add more cases based on other modules
    default:
      return "No summary available.";
  }
};

const SearchResultsTable = ({ results }) => {
  const [expandedModule, setExpandedModule] = useState(null);
  const [sortBy, setSortBy] = useState("module");
  const [sortDirection, setSortDirection] = useState("asc");

  const handleToggle = (module) => {
    setExpandedModule(expandedModule === module ? null : module);
  };

  const handleSort = (column) => {
    const direction = sortBy === column && sortDirection === "asc" ? "desc" : "asc";
    setSortBy(column);
    setSortDirection(direction);
  };

  const sortedResults = [...results].sort((a, b) => {
    const aValue = a[sortBy];
    const bValue = b[sortBy];
    if (aValue < bValue) return sortDirection === "asc" ? -1 : 1;
    if (aValue > bValue) return sortDirection === "asc" ? 1 : -1;
    return 0;
  });

  return (
    <div className="bg-gray-800 p-4 rounded-lg shadow-md">
      <div className="overflow-x-auto">
        <table className="min-w-full table-auto text-white">
          <thead className="bg-gray-700">
            <tr>
              <th
                className="px-4 py-2 text-left cursor-pointer hover:bg-gray-600"
                onClick={() => handleSort("module")}
              >
                Module
                {sortBy === "module" && (sortDirection === "asc" ? " ↑" : " ↓")}
              </th>
              <th
                className="px-4 py-2 text-left cursor-pointer hover:bg-gray-600"
                onClick={() => handleSort("risk_score")}
              >
                Risk Score
                {sortBy === "risk_score" && (sortDirection === "asc" ? " ↑" : " ↓")}
              </th>
              <th
                className="px-4 py-2 text-left cursor-pointer hover:bg-gray-600"
                onClick={() => handleSort("summary")}
              >
                Summary
                {sortBy === "summary" && (sortDirection === "asc" ? " ↑" : " ↓")}
              </th>
              <th className="px-4 py-2 text-left">Actions</th>
            </tr>
          </thead>
          <tbody>
            {sortedResults.map((result, index) => {
              const { module, risk_score, summary, raw } = result;
              const summaryText = generateSummary(module, summary);

              return (
                <React.Fragment key={index}>
                  <tr className="border-t border-gray-600 hover:bg-gray-600">
                    <td className="px-4 py-2">{module}</td>
                    <td className="px-4 py-2">{risk_score}</td>
                    <td className="px-4 py-2">{summaryText}</td>
                    <td className="px-4 py-2">
                      <button
                        onClick={() => handleToggle(module)}
                        className="text-purple-500 hover:text-purple-400"
                      >
                        {expandedModule === module ? "Collapse" : "Expand"}
                      </button>
                    </td>
                  </tr>
                  {expandedModule === module && (
                    <tr className="bg-gray-700">
                      <td colSpan="4" className="px-4 py-2">
                        {/* Condensed Display */}
                        <div className="max-w-full overflow-x-auto">
                          <div className="overflow-hidden">
                            {/* Make the JSON content scrollable and ensure it wraps */}
                            <pre className="text-sm whitespace-pre-wrap break-words max-w-full">
                              {/* Only show key fields for VirusTotal */}
                              {raw ? (
                                <div>
                                  <strong>Malicious:</strong> {raw.malicious} <br />
                                  <strong>Suspicious:</strong> {raw.suspicious} <br />
                                  <strong>Reputation:</strong> {raw.reputation} <br />
                                  <strong>Last Analysis Stats:</strong> 
                                  <pre>{JSON.stringify(raw.last_analysis_stats, null, 2)}</pre>
                                </div>
                              ) : (
                                <span>No data available</span>
                              )}
                            </pre>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default SearchResultsTable;
