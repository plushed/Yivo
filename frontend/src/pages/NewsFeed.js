import { useState, useEffect } from 'react';
import axios from 'axios';
import { useAuth } from "../context/AuthContext";
import { ViewColumnsIcon } from '@heroicons/react/24/outline';

export default function NewsFeed() {
  const { accessToken } = useAuth();
  const [feeds, setFeeds] = useState([]);
  const [loading, setLoading] = useState(true);
  const [layout, setLayout] = useState('card'); // card or table
  const [resultsPerPage, setResultsPerPage] = useState(5); // Default number of results per page
  const [currentPage, setCurrentPage] = useState(1);

  useEffect(() => {
    if (!accessToken) return;

    let didCancel = false;

    async function fetchRSSFeeds() {
      try {
        setLoading(true);
        const response = await axios.get(
          'https://fluffy-waffle-4xvwj5g4xvc5jwr-8000.app.github.dev/api/feeds/rss/articles/',
          {
            headers: {
              Authorization: `Bearer ${accessToken}`,
            }
          }
        );
        if (!didCancel) {
          setFeeds(response.data.articles || []);
        }
      } catch (error) {
        if (!didCancel) {
          console.error('Error fetching RSS feeds:', error);
        }
      } finally {
        if (!didCancel) {
          setLoading(false);
        }
      }
    }

    fetchRSSFeeds();

    return () => {
      didCancel = true; // cleanup on unmount to prevent state updates
    };
  }, [accessToken]);

  if (loading) {
    return (
      <div className="flex justify-center my-8">
        <div className="w-8 h-8 border-4 border-purple-600 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (feeds.length === 0) {
    return <div className="text-gray-400">No news articles available. Please check your feed settings.</div>;
  }

  // Pagination Logic
  const totalPages = Math.ceil(feeds.length / resultsPerPage);
  const startIndex = (currentPage - 1) * resultsPerPage;
  const currentFeeds = feeds.slice(startIndex, startIndex + resultsPerPage);

  const handleLayoutChange = (newLayout) => {
    setLayout(newLayout);
  };

  const handleResultsPerPageChange = (event) => {
    setResultsPerPage(Number(event.target.value));
    setCurrentPage(1); // Reset to the first page whenever results per page changes
  };

  const handlePageChange = (pageNumber) => {
    setCurrentPage(pageNumber);
  };

  return (
    <div>
      {/* Layout toggle icons */}
      <div className="flex justify-end gap-4 mb-4">
        <button
          onClick={() => handleLayoutChange('card')}
          className={`p-2 rounded-full ${layout === 'card' ? 'bg-purple-600 text-white' : 'bg-gray-800 text-gray-400'}`}
        >
          <ViewColumnsIcon className="h-6 w-6 text-gray-500" />
        </button>
        <button
          onClick={() => handleLayoutChange('table')}
          className={`p-2 rounded-full ${layout === 'table' ? 'bg-purple-600 text-white' : 'bg-gray-800 text-gray-400'}`}
        >
          <ViewColumnsIcon className="h-6 w-6 text-gray-500" />
        </button>
      </div>

      {/* Results per page selector */}
      <div className="mb-4">
        <label className="text-sm text-gray-400 mr-2">Results per page:</label>
        <select
          value={resultsPerPage}
          onChange={handleResultsPerPageChange}
          className="bg-gray-800 text-gray-400 border border-gray-700 rounded-md p-2"
        >
          <option value={5}>5</option>
          <option value={10}>10</option>
          <option value={15}>15</option>
        </select>
      </div>

      {/* Display Articles */}
      {layout === 'card' ? (
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {currentFeeds.map((feed, index) => {
            const publishedDate = new Date(feed.published);
            const formattedDate = publishedDate.toLocaleDateString('en-US', {
              weekday: 'short',
              year: 'numeric',
              month: 'short',
              day: 'numeric',
            });

            return (
              <div key={index} className="bg-gray-900 border border-gray-700 rounded-xl p-4 hover:shadow-lg transition group">
                <h2 className="text-lg font-semibold text-purple-300 group-hover:underline mb-2">
                  <a href={feed.link} target="_blank" rel="noopener noreferrer">{feed.title}</a>
                </h2>
                <p className="text-gray-400 text-sm line-clamp-4">{feed.summary}</p>
                <div className="text-gray-500 text-xs mt-2">Published: {formattedDate}</div>
                <div className="text-gray-500 text-xs mt-2">Source: {feed.feed_name || "Unknown Feed"}</div>
              </div>
            );
          })}
        </div>
      ) : (
        <table className="min-w-full table-auto bg-gray-900 border border-gray-700 rounded-xl text-sm">
  <thead>
    <tr className="text-left text-purple-300">
      <th className="py-2 px-3 border-b border-gray-700">Title</th>
      <th className="py-2 px-3 border-b border-gray-700">Summary</th>
      <th className="py-2 px-3 border-b border-gray-700">Source</th>
      <th className="py-2 px-3 border-b border-gray-700">Published</th>
      <th className="py-2 px-3 border-b border-gray-700">Link</th>
    </tr>
  </thead>
  <tbody>
    {currentFeeds.map((feed, index) => {
      const publishedDate = new Date(feed.published);
      const formattedDate = publishedDate.toLocaleDateString('en-US', {
        weekday: 'short',
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      });

      return (
        <tr key={index} className="text-gray-400 hover:bg-gray-800 align-top text-sm">
          <td className="py-2 px-3 border-b border-gray-700 max-w-xs break-words">{feed.title}</td>
          <td className="py-2 px-3 border-b border-gray-700 max-w-2xl whitespace-normal break-words">{feed.summary}</td>
          <td className="py-2 px-3 border-b border-gray-700">{feed.feed_name || "Unknown Feed"}</td>
          <td className="py-2 px-3 border-b border-gray-700">{formattedDate}</td>
          <td className="py-2 px-3 border-b border-gray-700">
            <a href={feed.link} target="_blank" rel="noopener noreferrer" className="text-purple-300 hover:underline">Read</a>
          </td>
        </tr>
      );
    })}
  </tbody>
</table>

      )}

      {/* Pagination controls */}
      <div className="flex justify-center mt-4">
        <button
          onClick={() => handlePageChange(currentPage - 1)}
          disabled={currentPage === 1}
          className="px-4 py-2 bg-purple-600 text-white rounded-l-md"
        >
          Prev
        </button>
        <span className="px-4 py-2 text-gray-400">{`Page ${currentPage} of ${totalPages}`}</span>
        <button
          onClick={() => handlePageChange(currentPage + 1)}
          disabled={currentPage === totalPages}
          className="px-4 py-2 bg-purple-600 text-white rounded-r-md"
        >
          Next
        </button>
      </div>
    </div>
  );
}
