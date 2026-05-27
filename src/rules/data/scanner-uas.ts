import type { UserAgentPattern } from "./ai-bots.js";

export const SCANNER_UA_PATTERNS: UserAgentPattern[] = [
  { name: "sqlmap", regex: /sqlmap/i },
  { name: "nikto", regex: /nikto/i },
  { name: "nuclei", regex: /nuclei/i },
  { name: "wpscan", regex: /wpscan/i },
  { name: "acunetix", regex: /acunetix/i },
  { name: "nessus", regex: /nessus/i },
  { name: "qualys", regex: /qualys/i },
  { name: "openvas", regex: /openvas/i },
  { name: "masscan", regex: /masscan/i },
  { name: "zgrab", regex: /zgrab/i },
  { name: "nmap", regex: /nmap/i },
  { name: "ffuf", regex: /ffuf/i },
  { name: "gobuster", regex: /gobuster/i },
  { name: "dirbuster", regex: /dirbuster/i },
  { name: "feroxbuster", regex: /feroxbuster/i },
  { name: "wfuzz", regex: /wfuzz/i },
  { name: "arachni", regex: /arachni/i },
  { name: "whatweb", regex: /whatweb/i },
  { name: "httpx", regex: /httpx/i },
  // Anchor katana to a slash + version to avoid matching Facebook Android app
  // ("com.facebook.katana"). Real katana scanner UA is e.g. "katana/v1.0".
  { name: "katana", regex: /\bkatana\/\d/i },
  { name: "subfinder", regex: /subfinder/i }
];
