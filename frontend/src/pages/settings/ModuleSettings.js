import React, { useState, useEffect } from "react";
import axiosInstance from "../../utils/AxiosInstance";

const defaultModules = {
  VirusTotal: { enabled: false, apiKey: "", weight: 1.0 },
  AlienVault: { enabled: false, apiKey: "", weight: 1.0 },
  "IBM X-Force": { enabled: false, apiKey: "", apiSecret: "", weight: 1.0 },
  Shodan: { enabled: false, apiKey: "", weight: 1.0 },
  APIVoid: { enabled: false, apiKey: "", weight: 1.0 },
  AbuseIPDB: { enabled: false, apiKey: "", weight: 1.0 },
  GreyNoise: { enabled: false, apiKey: "", weight: 1.0 },
  URLScan: { enabled: false, apiKey: "", weight: 1.0 },
  PhishLabs: { enabled: false, apiKey: "", weight: 1.0 },
};

const modulesThatNeedSecret = [
  "IBM X-Force",
  // Add other modules that require both apiKey and apiSecret
];

const ModuleSettings = () => {
  const [modules, setModules] = useState(defaultModules);
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [visibility, setVisibility] = useState({});
  const [moduleDescriptions, setModuleDescriptions] = useState({});

  useEffect(() => {
    const fetchSettings = async () => {
      try {
        const res = await axiosInstance.get("/modules/settings/");
        const fetched = res.data;

        const merged = { ...defaultModules };
        
        fetched
        .filter((m) => m.type === "api")
        .forEach((module) => {
          const name = module.moduleName;
          merged[name] = {
            ...defaultModules[name],
            enabled: module.enabled ?? false,
            apiKey: module.apiKey ?? "",
            apiSecret: module.apiSecret ?? "",
            weight: module.weight ?? 1.0,
          };

          // Set descriptions and website links
          setModuleDescriptions((prevDescriptions) => ({
            ...prevDescriptions,
            [name]: {
              description: module.description || "No description available",
              website: module.website || "#", // Default to "#" if no website is provided
            },
          }));
        });

        setModules(merged);
      } catch (err) {
        console.error("Could not fetch module settings", err);
        setMessage("Error fetching settings.");
      }
    };
    fetchSettings();
  }, []);

  const handleToggle = (moduleName) => {
    setModules((prev) => ({
      ...prev,
      [moduleName]: {
        ...prev[moduleName],
        enabled: !prev[moduleName].enabled,
      },
    }));
  };

  const handleChange = (moduleName, field, value) => {
    setModules((prev) => {
      const updatedModule = {
        ...prev[moduleName],
        [field]: value,
      };

      if ((field === "apiKey" || field === "apiSecret") && value.trim() !== "") {
        updatedModule.enabled = true;
      }

      return {
        ...prev,
        [moduleName]: updatedModule,
      };
    });
  };

  const handleWeightChange = (moduleName, value) => {
    setModules((prev) => ({
      ...prev,
      [moduleName]: {
        ...prev[moduleName],
        weight: value,
      },
    }));
  };

  const toggleVisibility = (moduleName, field) => {
    setVisibility((prev) => ({
      ...prev,
      [`${moduleName}-${field}`]: !prev[`${moduleName}-${field}`],
    }));
  };

  const handleSave = async () => {
    setLoading(true);
    try {
      const modulesData = Object.entries(modules).map(([module, config]) => ({
        moduleName: module,
        enabled: config.enabled,
        apiKey: config.apiKey || "",
        apiSecret: config.apiSecret || "",
        weight: config.weight,
      }));
      await axiosInstance.post("/modules/settings/", modulesData);
      setMessage("Settings saved successfully!");
    } catch (err) {
      console.error("Failed to save settings", err);
      setMessage("Error saving settings.");
    }
    setLoading(false);
  };

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <h1 className="text-3xl font-bold mb-6 text-purple-500">Module Settings</h1>
      {Object.entries(modules).map(([module, config]) => (
        <div key={module} className="mb-6 p-4 border border-gray-700 rounded bg-gray-800 text-white">
          <div className="flex items-center justify-between">
            <span className="text-xl font-semibold">{module}</span>
            <label className="inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                value=""
                checked={config.enabled}
                onChange={() => handleToggle(module)}
                className="sr-only peer"
              />
              <div className="w-11 h-6 bg-gray-600 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-purple-500 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-0.5 after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-purple-600 relative" />
              <span className="ml-3 text-sm font-medium text-gray-200">
                {config.enabled ? "Enabled" : "Disabled"}
              </span>
            </label>
          </div>
          <div className="mt-4 space-y-2">
            <div className="relative">
              <input
                type={visibility[`${module}-apiKey`] ? "text" : "password"}
                placeholder="API Key"
                value={config.apiKey}
                onChange={(e) => handleChange(module, "apiKey", e.target.value)}
                className="w-full p-2 bg-gray-700 border border-gray-600 rounded"
              />
              <button
                type="button"
                onClick={() => toggleVisibility(module, "apiKey")}
                className="absolute top-2 right-2 text-sm text-gray-300"
              >
                {visibility[`${module}-apiKey`] ? "Hide" : "Show"}
              </button>
            </div>

            {modulesThatNeedSecret.includes(module) && "apiSecret" in config && (
              <div className="relative">
                <input
                  type={visibility[`${module}-apiSecret`] ? "text" : "password"}
                  placeholder="API Secret"
                  value={config.apiSecret}
                  onChange={(e) => handleChange(module, "apiSecret", e.target.value)}
                  className="w-full p-2 bg-gray-700 border border-gray-600 rounded"
                />
                <button
                  type="button"
                  onClick={() => toggleVisibility(module, "apiSecret")}
                  className="absolute top-2 right-2 text-sm text-gray-300"
                >
                  {visibility[`${module}-apiSecret`] ? "Hide" : "Show"}
                </button>
              </div>
            )}

            {/* Weight Slider */}
            <div className="mt-4">
              <label htmlFor={`${module}-weight`} className="block text-sm font-medium text-gray-200">
                Weight: {config.weight.toFixed(1)}
              </label>
              <input
                id={`${module}-weight`}
                type="range"
                min="0.1"
                max="2"
                step="0.1"
                value={config.weight}
                onChange={(e) => handleWeightChange(module, parseFloat(e.target.value))}
                className="w-full mt-2"
              />
            </div>

            {/* Tooltip and Website */}
            <div className="mt-4 text-sm text-gray-300">
              <span
                className="cursor-pointer"
                title={moduleDescriptions[module]?.description}
              >
                Hover for description
              </span>{" "}
              <a
                href={moduleDescriptions[module]?.website}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-400 underline ml-2"
              >
                {moduleDescriptions[module]?.website ? "Visit Website" : "No Website"}
              </a>
            </div>
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

export default ModuleSettings;
