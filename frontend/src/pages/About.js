import React from "react";

const About = () => {
  return (
      <div className="max-w-3xl mx-auto bg-gray-800 p-6 rounded-lg shadow-lg">
        <p className="text-lg text-gray-300 leading-relaxed">
          Yivo is a solo-developed cybersecurity platform designed to bridge critical gaps in the threat intelligence landscape. The core mission is to empower security professionals with actionable insights by centralizing and streamlining access to diverse intelligence sources. Built with modularity in mind, Yivo is structured around independent but interconnected apps that each serve a focused purpose.
        </p>
        <p className="mt-4 text-lg text-gray-300 leading-relaxed">
          The first module, Search, enables users to perform deep investigations on indicators of compromise (IOCs)—such as IPs, domains, URLs, and hashes—by aggregating and correlating risk data from both open-source and commercial feeds. This unified approach gives users a comprehensive view of an indicator’s threat profile, reducing the noise and fragmentation typically found in threat intel workflows.
        </p>
        <p className="mt-4 text-lg text-gray-300 leading-relaxed">
          Future modules will extend Yivo’s capabilities with automated detection, enrichment tools, and integration with frameworks like MITRE ATT&CK, aiming to become a robust assistant in proactive and reactive cybersecurity efforts.
        </p>
      </div>
  );
};

export default About;
