import { useState } from 'react';
import NewsFeed from './NewsFeed';
// (later) import IDFeed from './id/IDFeed';
// (more future tabs/components)

const tabs = [
  { name: 'News', key: 'news' },
  { name: 'Id', key: 'id' },  // for future ID work
  // you can easily add more tabs later here
];

export default function DiscoverPage() {
  const [activeTab, setActiveTab] = useState('news');

  return (
    <div className="p-4 max-w-5xl mx-auto pt-8 lg:pt-12">
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
        {activeTab === 'news' && <NewsFeed />}
        {/* later: {activeTab === 'id' && <IDFeed />} */}
      </div>
    </div>
  );
}
