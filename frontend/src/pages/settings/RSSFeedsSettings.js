import React, { useState, useEffect } from "react";
import axiosInstance from "../../utils/AxiosInstance";

const defaultRSSFeeds = {
  "ThreatPost Security News": { enabled: true, url: "https://threatpost.com/feed/" },
  "BleepingComputer Updates": { enabled: true, url: "https://www.bleepingcomputer.com/feed/" },
};

const RSSFeedsSettings = () => {
  const [builtinFeeds, setBuiltinFeeds] = useState(defaultRSSFeeds);
  const [customFeeds, setCustomFeeds] = useState([]);
  const [newFeedName, setNewFeedName] = useState("");
  const [newFeedUrl, setNewFeedUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    const fetchRSSFeeds = async () => {
      try {
        const res = await axiosInstance.get("/feeds/rss/settings/");
        const { builtin = {}, custom = [] } = res.data;
        setBuiltinFeeds(builtin);
        setCustomFeeds(custom);
      } catch (err) {
        console.error("Error fetching RSS feed settings", err);
        setMessage("Error loading RSS feeds.");
      }
    };
    fetchRSSFeeds();
  }, []);

  const toggleBuiltinFeed = (feedName) => {
    setBuiltinFeeds((prev) => ({
      ...prev,
      [feedName]: {
        ...prev[feedName],
        enabled: !prev[feedName].enabled,
      },
    }));
  };

  const handleAddCustomFeed = () => {
    if (!newFeedName.trim() || !newFeedUrl.trim()) return;
    setCustomFeeds((prev) => [
      ...prev,
      { name: newFeedName.trim(), url: newFeedUrl.trim(), enabled: true },
    ]);
    setNewFeedName("");
    setNewFeedUrl("");
  };

  const toggleCustomFeed = (index) => {
    setCustomFeeds((prev) =>
      prev.map((feed, idx) =>
        idx === index ? { ...feed, enabled: !feed.enabled } : feed
      )
    );
  };

  const removeCustomFeed = (index) => {
    setCustomFeeds((prev) => prev.filter((_, idx) => idx !== index));
  };

  const handleSave = async () => {
    setLoading(true);
    try {
      await axiosInstance.post("/feeds/rss/settings/", {
        builtin: builtinFeeds,
        custom: customFeeds,
      });
      setMessage("Feeds saved successfully!");
    } catch (err) {
      console.error("Error saving RSS feeds", err);
      setMessage("Error saving feeds.");
    }
    setLoading(false);
  };

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <h2 className="text-2xl font-bold mb-6">RSS Feed Settings</h2>

      {/* Built-in Feeds */}
      <div className="mb-10">
        <h3 className="text-xl font-semibold mb-4">Built-in Feeds</h3>
        {Object.entries(builtinFeeds).map(([name, feed]) => (
          <div key={name} className="flex items-center justify-between mb-4 p-4 border border-gray-700 rounded bg-gray-800">
            <div>
              <p className="text-lg font-medium">{name}</p>
              <p className="text-sm text-gray-400">{feed.url}</p>
            </div>
            <label className="inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={feed.enabled}
                onChange={() => toggleBuiltinFeed(name)}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-600 rounded-full peer peer-checked:bg-purple-600 relative after:absolute after:top-0.5 after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:after:translate-x-full" />
              <span className="ml-3 text-sm text-gray-300">
                {feed.enabled ? "Enabled" : "Disabled"}
              </span>
            </label>
          </div>
        ))}
      </div>

      {/* Custom Feeds */}
      <div className="mb-10">
        <h3 className="text-xl font-semibold mb-4">Custom Feeds</h3>

        {customFeeds.map((feed, idx) => (
          <div key={idx} className="flex items-center justify-between mb-4 p-4 border border-gray-700 rounded bg-gray-800">
            <div>
              <p className="text-lg font-medium">{feed.name}</p>
              <p className="text-sm text-gray-400">{feed.url}</p>
            </div>
            <div className="flex items-center space-x-4">
              <label className="inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={feed.enabled}
                  onChange={() => toggleCustomFeed(idx)}
                  className="sr-only peer"
                />
                <div className="w-11 h-6 bg-gray-600 rounded-full peer peer-checked:bg-purple-600 relative after:absolute after:top-0.5 after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:after:translate-x-full" />
              </label>
              <button
                onClick={() => removeCustomFeed(idx)}
                className="text-red-400 hover:text-red-500 text-sm"
              >
                Remove
              </button>
            </div>
          </div>
        ))}

        {/* Add New Custom Feed */}
        <div className="mt-6 space-y-4">
          <input
            type="text"
            placeholder="Feed Name"
            value={newFeedName}
            onChange={(e) => setNewFeedName(e.target.value)}
            className="w-full p-2 bg-gray-700 text-white rounded"
          />
          <input
            type="text"
            placeholder="Feed URL"
            value={newFeedUrl}
            onChange={(e) => setNewFeedUrl(e.target.value)}
            className="w-full p-2 bg-gray-700 text-white rounded"
          />
          <button
            onClick={handleAddCustomFeed}
            className="mt-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded"
          >
            Add Feed
          </button>
        </div>
      </div>

      {/* Save Button */}
      <button
        onClick={handleSave}
        disabled={loading}
        className={`w-full py-3 bg-purple-600 hover:bg-purple-700 text-white rounded ${loading ? "opacity-50 cursor-not-allowed" : ""}`}
      >
        {loading ? "Saving..." : "Save All Feeds"}
      </button>

      {message && <p className="mt-4 text-center text-green-400">{message}</p>}
    </div>
  );
};

export default RSSFeedsSettings;
