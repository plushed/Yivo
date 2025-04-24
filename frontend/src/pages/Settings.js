import { useState } from 'react';
import ModuleSettings from './settings/ModuleSettings';
import BuildinFeeds from './settings/BuildinFeeds';
import ProfileSettings from './settings/ProfileSettings';

const tabs = [
  { name: 'Profile', key: 'profile' },
  { name: 'API-Connected Feeds', key: 'api-feeds' },
  { name: 'Built-in Feeds', key: 'automatic-feeds' },
];

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState('profile');

  return (
    <div className="p-4 max-w-4xl mx-auto">
      <div className="border-b border-gray-700 mb-6">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`pb-2 px-3 text-sm font-medium ${
                activeTab === tab.key
                  ? 'border-b-2 border-purple-500 text-purple-300'
                  : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              {tab.name}
            </button>
          ))}
        </nav>
      </div>

      <div>
        {activeTab === 'api-feeds' && <ModuleSettings />}
        {activeTab === 'automatic-feeds' && <BuildinFeeds />}
        {activeTab === 'profile' && <ProfileSettings />}
      </div>
    </div>
  );
}
