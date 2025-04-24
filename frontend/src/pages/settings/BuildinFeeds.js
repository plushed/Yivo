import React, { useState, useEffect } from "react";
import axiosInstance from "../../utils/AxiosInstance";

const defaultBuiltinFeeds = {
  "Onionoo": { enabled: false, weight: 1.0 },
  "CINSscore": { enabled: false, weight: 1.0 },
  "OpenPhish": { enabled: false, weight: 1.0 },
};

const BuiltinFeedSettings = () => {
  const [feeds, setFeeds] = useState(defaultBuiltinFeeds);
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [feedDescriptions, setFeedDescriptions] = useState({});

  useEffect(() => {
    const fetchSettings = async () => {
      try {
        const res = await axiosInstance.get("/modules/settings/");
        const fetched = res.data;

        const merged = { ...defaultBuiltinFeeds };

        fetched
          .filter((f) => f.type === "builtin")
          .forEach((feed) => {
            const name = feed.moduleName;
            merged[name] = {
              enabled: feed.enabled ?? false,
              weight: feed.weight ?? 1.0,
            };

            setFeedDescriptions((prev) => ({
              ...prev,
              [name]: {
                description: feed.description || "No description available",
                website: feed.website || "#",
              },
            }));
          });

        setFeeds(merged);
      } catch (err) {
        console.error("Could not fetch builtin feed settings", err);
        setMessage("Error fetching settings.");
      }
    };
    fetchSettings();
  }, []);

  const handleToggle = (feedName) => {
    setFeeds((prev) => ({
      ...prev,
      [feedName]: {
        ...prev[feedName],
        enabled: !prev[feedName].enabled,
      },
    }));
  };

  const handleWeightChange = (feedName, value) => {
    setFeeds((prev) => ({
      ...prev,
      [feedName]: {
        ...prev[feedName],
        weight: value,
      },
    }));
  };

  const handleSave = async () => {
    setLoading(true);
    try {
      const feedsData = Object.entries(feeds).map(([feed, config]) => ({
        moduleName: feed,
        enabled: config.enabled,
        weight: config.weight,
      }));
      await axiosInstance.post("/modules/settings/", feedsData);
      setMessage("Settings saved successfully!");
    } catch (err) {
      console.error("Failed to save settings", err);
      setMessage("Error saving settings.");
    }
    setLoading(false);
  };

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <h1 className="text-3xl font-bold mb-6 text-purple-500">Builtin Feed Settings</h1>
      {Object.entries(feeds).map(([feed, config]) => (
        <div key={feed} className="mb-6 p-4 border border-gray-700 rounded bg-gray-800 text-white">
          <div className="flex items-center justify-between">
            <span className="text-xl font-semibold">{feed}</span>
            <label className="inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={config.enabled}
                onChange={() => handleToggle(feed)}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-purple-500 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-0.5 after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600 relative" />
              <span className="ml-3 text-sm font-medium text-gray-200">
                {config.enabled ? "Enabled" : "Disabled"}
              </span>
            </label>
          </div>

          <div className="mt-4">
            <label htmlFor={`${feed}-weight`} className="block text-sm font-medium text-gray-200">
              Weight: {config.weight.toFixed(1)}
            </label>
            <input
              id={`${feed}-weight`}
              type="range"
              min="0.1"
              max="2"
              step="0.1"
              value={config.weight}
              onChange={(e) => handleWeightChange(feed, parseFloat(e.target.value))}
              className="w-full mt-2"
            />
          </div>

          <div className="mt-4 text-sm text-gray-300">
            <span
              className="cursor-pointer"
              title={feedDescriptions[feed]?.description}
            >
              Hover for description
            </span>{" "}
            <a
              href={feedDescriptions[feed]?.website}
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-400 underline ml-2"
            >
              {feedDescriptions[feed]?.website ? "Visit Website" : "No Website"}
            </a>
          </div>
        </div>
      ))}
      <button
        onClick={handleSave}
        disabled={loading}
        className={`mt-6 px-6 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded ${loading ? "opacity-50 cursor-not-allowed" : ""}`}
      >
        {loading ? "Saving..." : "Save All"}
      </button>
      {message && <p className="mt-4 text-sm text-green-400">{message}</p>}
    </div>
  );
};

export default BuiltinFeedSettings;
