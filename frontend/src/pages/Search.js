import React, { useState } from "react";
import axios from "axios";
import { useAuth } from "../context/AuthContext";
import SearchResultsTable from "./SearchResultsTable";

// Validation functions for each indicator type
const validateHash = (val) => /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(val);
const validateIP = (val) => /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(val);
const validateEmail = (val) => /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(val);
const validateDomain = (val) => /^[a-z0-9]+([-.][a-z0-9]+)*\.[a-z]{2,}$/i.test(val);
const validateURL = (val) => /^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}(\/.*)?$/i.test(val) && val.includes('/');

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
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const { accessToken } = useAuth();

  const handleSearch = async (e) => {
    e.preventDefault();

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
    setError(null);
    setLoading(true);

    try {
      const response = await axios.post(
        "https://fluffy-waffle-4xvwj5g4xvc5jwr-8000.app.github.dev/api/search/",
        {
          indicator: query,
          indicator_type: detectedType,
        },
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
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
    setIndicatorType(detectIndicatorType(value));
  };

  return (
    <div className="py-8 px-4">
      <div className="flex items-center justify-center">
        <form onSubmit={handleSearch} className="flex items-center max-w-md w-full">
          <label htmlFor="simple-search" className="sr-only">Search</label>
          <div className="relative w-full">
            <div className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none">
              <svg className="w-5 h-5 text-gray-500 dark:text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 18 20">
                <path stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 5v10M3 5a2 2 0 1 0 0-4 2 2 0 0 0 0 4Zm0 10a2 2 0 1 0 0 4 2 2 0 0 0 0-4Zm12 0a2 2 0 1 0 0 4 2 2 0 0 0 0-4Zm0 0V6a3 3 0 0 0-3-3H9m1.5-2-2 2 2 2" />
              </svg>
            </div>
            <input
              type="text"
              id="simple-search"
              className="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full pl-10 p-2.5 dark:bg-gray-700 dark:border-gray-600 dark:placeholder-gray-400 dark:text-white dark:focus:ring-blue-500 dark:focus:border-blue-500"
              placeholder="Search IP, domain, URL, hash, or email"
              value={query}
              onChange={handleChange}
              required
            />
          </div>
          <button
            type="submit"
            className="p-2.5 ml-2 text-sm font-medium text-white bg-purple-600 rounded-lg border border-purple-600 hover:bg-purple-700 focus:ring-4 focus:outline-none focus:ring-purple-300 dark:bg-purple-500 dark:hover:bg-purple-600 dark:focus:ring-purple-700"
          >
            <svg className="w-5 h-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 20 20">
              <path stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="m19 19-4-4m0-7A7 7 0 1 1 1 8a7 7 0 0 1 14 0Z" />
            </svg>
            <span className="sr-only">Search</span>
          </button>
        </form>
      </div>

      {loading && (
        <div className="flex justify-center my-4">
          <div className="w-8 h-8 border-4 border-purple-600 border-t-transparent rounded-full animate-spin"></div>
        </div>
      )}

      {indicatorType && (
        <div className="text-purple-600 text-center mt-2 mb-4">
          Detected Indicator Type: <strong>{indicatorType}</strong>
        </div>
      )}

      {error && <div className="text-red-500 text-center">{error}</div>}

      {results.length > 0 && (
        <div className="mt-8">
          <SearchResultsTable results={results} />
        </div>
      )}
    </div>
  );
};

export default Search;
