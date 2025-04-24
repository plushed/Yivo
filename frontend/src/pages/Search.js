import React, { useState } from "react";
import axios from "axios";
import SearchResultsTable from "./SearchResultsTable";

// Validation functions for each indicator type
const validateHash = (val) => /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(val);
const validateIP = (val) => /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(val);
const validateEmail = (val) => /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(val);
const validateDomain = (val) => /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(val);
const validateURL = (val) => /^(https?:\/\/)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(val);

// Auto-detect indicator type
const detectIndicatorType = (val) => {
  if (validateEmail(val)) return "email";
  if (validateIP(val)) return "ip";
  if (validateURL(val)) return "url";
  if (validateDomain(val)) return "domain";
  if (validateHash(val)) return "hash";
  return null;
};

const Search = () => {
  const [query, setQuery] = useState("");
  const [indicatorType, setIndicatorType] = useState(null);
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSearch = async () => {
    if (!query) {
      setError("Please enter a search query.");
      return;
    }

    const detectedType = detectIndicatorType(query);
    if (!detectedType) {
      setError("Unable to detect the indicator type or invalid format.");
      return;
    }

    setIndicatorType(detectedType);
    setLoading(true);
    setError(null);

    try {
      const response = await axios.post(
        "https://fluffy-waffle-4xvwj5g4xvc5jwr-8000.app.github.dev/api/search/",
        {
          indicator: query,
          indicator_type: detectedType,
        },
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("access_token")}`,
          },
        }
      );
      setResults(Object.values(response.data.results));
    } catch (err) {
      console.error(err);
      setError("An error occurred while fetching the results.");
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e) => {
    const value = e.target.value;
    setQuery(value);
    const type = detectIndicatorType(value);
    setIndicatorType(type);
  };

  return (
    <div className="text-center">
      <h1 className="text-4xl font-bold text-purple-500">Search</h1>
      <div className="mt-4">
        <label className="block text-lg text-white">Search Query:</label>
        <input
          type="text"
          className="mt-2 p-2 bg-gray-700 text-white w-64"
          value={query}
          onChange={handleChange}
          placeholder="Enter IP, domain, URL, hash, or email"
        />
        {indicatorType && (
          <div className="mt-2 text-sm text-gray-300">
            Detected Type: <span className="text-purple-400 font-medium">{indicatorType}</span>
          </div>
        )}
      </div>

      <div className="mt-6">
        <button
          onClick={handleSearch}
          className="px-4 py-2 bg-purple-600 text-white rounded hover:bg-purple-500"
        >
          {loading ? "Searching..." : "Search"}
        </button>
      </div>

      {error && <div className="mt-4 text-red-500">{error}</div>}

      <div className="mt-6">
        {results.length > 0 && (
          <div>
            <h2 className="text-xl text-white">Results:</h2>
            <SearchResultsTable results={results} /> {/* Display results in table */}
          </div>
        )}
      </div>
    </div>
  );
};

export default Search;
