import React, { useState } from "react";

// Function to generate a brief summary for each module
const generateSummary = (module, data) => {
  switch (module) {
    case "AbuseIPDB":
      return `${data.abuseConfidenceScore}% confidence, ${data.totalReports} reports, ${data.countryCode}`;
    case "VirusTotal":
      return `${data.last_analysis_stats.malicious} malicious, ${data.last_analysis_stats.suspicious} suspicious, reputation ${data.reputation}`;
    // Add more cases based on other modules
    default:
      return "No summary available.";
  }
};

const SearchResultsTable = ({ results }) => {
  const [expandedModule, setExpandedModule] = useState(null);

  const handleToggle = (module) => {
    setExpandedModule(expandedModule === module ? null : module);
  };

  return (
    <div className="overflow-x-auto bg-gray-800 rounded-lg shadow-lg">
      <table className="min-w-full table-auto text-white">
        <thead>
          <tr>
            <th className="px-4 py-2 text-left">Module</th>
            <th className="px-4 py-2 text-left">Risk Score</th>
            <th className="px-4 py-2 text-left">Key Info Summary</th>
            <th className="px-4 py-2 text-left">Actions</th>
          </tr>
        </thead>
        <tbody>
          {results.map((result, index) => {
            const { module, score, data } = result;
            const summary = generateSummary(module, data);

            return (
              <React.Fragment key={index}>
                <tr>
                  <td className="px-4 py-2">{module}</td>
                  <td className="px-4 py-2">{score}</td>
                  <td className="px-4 py-2">{summary}</td>
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
                  <tr>
                    <td colSpan="4" className="bg-gray-700 px-4 py-2">
                      <pre className="text-sm overflow-x-auto">{JSON.stringify(data, null, 2)}</pre>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

export default SearchResultsTable;
