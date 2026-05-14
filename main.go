package main

import (
    "bufio"
    "encoding/csv"
    "encoding/json"
    "flag"
    "fmt"
    "html/template"
    "io"
    "log"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
    "sort"
    "strconv"
    "strings"
    "sync"
    "time"

	"net"
	"io/ioutil"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/tcpassembly"
    "github.com/google/gopacket/tcpassembly/tcpreader"
    "github.com/gorilla/websocket"
    "github.com/miekg/dns"

)

// ----------------------------------------------------------------------------
// Datenstrukturen
// ----------------------------------------------------------------------------

type SniffEvent struct {
    PacketNum int    `json:"packet_num"`
    Timestamp string `json:"timestamp"`
    Type      string `json:"type"` // "DNS" oder "TLS"
    IP        string `json:"ip"`
    MAC       string `json:"mac"`
    QuerySNI  string `json:"query_sni"`
}

type NetworkInterfaceInfo struct {
    Name        string `json:"Name"`
    Description string `json:"Description"`
}

type EventFilter struct {
    Timestamp string
    Type      string
    IP        string
    MAC       string
    SNI       string
}

type FilterMessage struct {
    Type   string      `json:"type"` // z. B. "setFilter"
    Filter EventFilter `json:"filter"`
    Live   bool        `json:"live"`
}

type PagedEventsResponse struct {
    Events       []SniffEvent `json:"events"`
    TotalMatches int          `json:"total_matches"`
    Page         int          `json:"page"`
    Limit        int          `json:"limit"`
}

type wsMessage struct {
    Type    string      `json:"type"`    // "new" oder "error"
    Payload interface{} `json:"payload"` // z. B. SniffEvent oder Fehlermeldung
}

// ----------------------------------------------------------------------------
// Globale Variablen
// ----------------------------------------------------------------------------

var (
    events   []SniffEvent
    eventsMu sync.RWMutex

    packetCounter   int
    packetCounterMu sync.Mutex

    handle    *pcap.Handle
    capturing bool
    captureMu sync.Mutex
    stopChan  chan struct{}

    currentPcapFile  string
    uploadedPcapFile string

    currentWSConn      *websocket.Conn
    currentClientState *ClientState
    wsClientsMu        sync.Mutex

    flowInfoMap = make(map[string]*FlowInfo)
    flowInfoMu  sync.RWMutex

    hasPrivileges bool
)

// FlowInfo speichert z. B. MAC für einen bestimmten Flow
type FlowInfo struct {
    MAC string
}

// ClientState speichert den aktuellen Filter und ob „Live“ aktiv ist
type ClientState struct {
    Filter EventFilter
    Live   bool
}

// ----------------------------------------------------------------------------
// HTML Templates
// ----------------------------------------------------------------------------

var mainTemplate = template.Must(template.New("main").Parse(
    `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"/>
    <title>DNS/TLS Sniffer</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        table { border-collapse: collapse; width: 100%; margin-top: 1rem; table-layout: fixed; }
        th, td { border: 1px solid #ddd; padding: 8px; word-wrap: break-word; }
        th { background: #f2f2f2; }
        .filters { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 10px 0; }
        .filters label { font-size: 0.9em; margin-bottom: 5px; }
        input[type="text"] { width: 100%; box-sizing: border-box; }
        .status { margin-bottom: 1rem; font-weight: bold; }
        button { padding: 8px 16px; font-size: 1em; cursor: pointer; }
        .interface-select { margin-bottom: 10px; display: flex; flex-direction: column; }
        .interface-select select { padding: 6px; font-size: 1em; }
        .pcap-loader { margin-top: 1rem; }
        h1, h2 { margin-top: 0; }
        .paging { margin: 10px 0; }
        .paging button { margin-right: 5px; }
        .paging select { padding: 6px; font-size: 1em; }

        .button-group {
            display: flex;
            flex-wrap: wrap;
            gap: 10px; 
            margin-bottom: 10px; 
        }
        .button-group button {
            flex: 1; 
            min-width: 150px; 
        }
        .warning {
            background-color: #fff3cd;
            color: #856404;
            padding: 10px;
            border: 1px solid #ffeeba;
            border-radius: 4px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
<div class="container">
    <h1>DNS over HTTPS Domain Name Sniffer</h1>
    <p>Version 8.1.2 - &copy; Reto Sch&auml;dler. <a href="https://www.fingerprint.ch" target="_blank" rel="noopener noreferrer">https://www.fingerprint.ch</a></p>

    <div class="status">Current Status: <span id="status">- unknown -</span></div>

    {{if not .HasPrivileges}}
    <div class="warning">
        <strong>Warning:</strong> The program is not running with administrator/root privileges. Some functions may be restricted.
    </div>
    {{end}}

    <div class="interface-select">
        <label for="ifaceSelect">Select Network Interface:</label>
        <select id="ifaceSelect"></select>
    </div>

    <div class="button-group">
        <button onclick="startSniffer()">Start Sniffer</button>
        <button onclick="stopSniffer()">Stop Sniffer</button>
    </div>

    <div class="pcap-loader">
        <h2>Load PCAP File (Offline Mode)</h2>
        <style>
            #pcapFile {
                display: none;
            }
            .button {
                display: inline-block;
                padding: 8px 16px;
                cursor: pointer;
                background-color: #e0e0e0; 
                color: #000; 
                border: 1px solid #ccc; 
                border-radius: 4px;
                font-size: 16px;
                text-align: center;
            }
            .button:hover {
                background-color: #d6d6d6; 
            }
            .button-container {
                display: flex;
                align-items: center;
                gap: 10px;
            }
            .file-name {
                font-size: 14px;
                color: #333;
                max-width: 200px;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }
        </style>

        <div class="button-container">
            <label for="pcapFile" class="button">
                Select File
            </label>
            <button class="button" id="loadButton" onclick="uploadPCAP()">Load PCAP</button>
            <span id="fileName" class="file-name">No file selected</span>
        </div>
        <input type="file" id="pcapFile" accept=".pcap,.pcapng,.cap" />
    </div>

    <script>
        document.getElementById('pcapFile').addEventListener('change', function () {
            const fileInput = this;
            const fileNameSpan = document.getElementById('fileName');
            const loadButton = document.getElementById('loadButton');

            if (fileInput.files && fileInput.files.length > 0) {
                const fileName = fileInput.files[0].name;
                fileNameSpan.textContent = fileName;
                loadButton.textContent = "Load " + fileName;
            } else {
                fileNameSpan.textContent = "No file selected";
                loadButton.textContent = "Load PCAP";
            }
        });
    </script>

    <div>
        <h2>CSV Export</h2>
        <div class="button-group">
            <button onclick="exportCSV()">Export as CSV (All)</button>
            <button onclick="exportCSVFiltered()">Export as CSV (Filtered)</button>
        </div>
    </div>

    <h2>Filter / Paging</h2>
    <div class="filters">
        <div>
            <label for="filterTimestamp">Timestamp contains</label>
            <input type="text" id="filterTimestamp" onkeydown="enterFilter(event)" />
        </div>
        <div>
            <label for="filterType">Type (DNS/TLS)</label>
            <input type="text" id="filterType" onkeydown="enterFilter(event)" />
        </div>
        <div>
            <label for="filterIP">IP contains</label>
            <input type="text" id="filterIP" onkeydown="enterFilter(event)" />
        </div>
        <div>
            <label for="filterMAC">MAC contains</label>
            <input type="text" id="filterMAC" onkeydown="enterFilter(event)" />
        </div>
        <div>
            <label for="filterSNI">Query/SNI contains</label>
            <input type="text" id="filterSNI" onkeydown="enterFilter(event)" />
        </div>
    </div>
    <button onclick="applyFilter()">Apply Filter</button>

    <div class="paging">
        <button onclick="prevPage()">Previous Page</button>
        <select id="pageSelect"
                onchange="pageSelectChanged(this.value)"
                onclick="refreshPageDropdown()"
                onmouseover="refreshPageDropdown()">
        </select>
        <button onclick="nextPage()">Next Page</button>
    </div>

    <table id="eventsTable">
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Type</th>
                <th>IP</th>
                <th>MAC</th>
                <th>Query/SNI</th>
            </tr>
        </thead>
        <tbody></tbody>
    </table>
</div>

<script>
// Paging
let currentPage = 1;
let totalPages = 1;
const pageLimit = 2500;

// Filter
let filterTimestamp = "";
let filterType = "";
let filterIP = "";
let filterMAC = "";
let filterSNI = "";

// WebSocket
let socket = null;
let liveRowCount = 0; // Anzahl "Live"-Einträge auf aktueller Seite

function enterFilter(event) {
    if (event.key === "Enter") {
        applyFilter();
    }
}

function isOnLatestPage() {
    return currentPage === totalPages;
}

function refreshPageDropdown() {
    loadEvents();
}

function applyFilter() {
    filterTimestamp = document.getElementById('filterTimestamp').value;
    filterType = document.getElementById('filterType').value;
    filterIP = document.getElementById('filterIP').value;
    filterMAC = document.getElementById('filterMAC').value;
    filterSNI = document.getElementById('filterSNI').value;

    currentPage = 1;
    loadEvents();
    sendFilterToServer();
}

function pageSelectChanged(newVal) {
    let newPage = parseInt(newVal);
    if (!isNaN(newPage)) {
        currentPage = newPage;
        loadEvents();
    }
}

function updatePageDropdown() {
    const sel = document.getElementById('pageSelect');
    sel.innerHTML = '';

    for (let i = 1; i <= totalPages; i++) {
        const opt = document.createElement('option');
        opt.value = i;
        opt.textContent = "Page " + i;
        sel.appendChild(opt);
    }

    // Falls keine Treffer, wenigstens Page 1 ...
    if (totalPages === 0) {
        const opt = document.createElement('option');
        opt.value = 1;
        opt.textContent = "Page 1";
        sel.appendChild(opt);
        totalPages = 1;
    }

    sel.value = currentPage;
}

function nextPage() {
    if (currentPage < totalPages) {
        currentPage++;
        loadEvents();
    }
}

function prevPage() {
    if (currentPage > 1) {
        currentPage--;
        loadEvents();
    }
}

function loadEvents() {
    const url = new URL('/api/events', window.location.origin);
    url.searchParams.set('page', currentPage);
    url.searchParams.set('limit', pageLimit);
    url.searchParams.set('timestamp', filterTimestamp);
    url.searchParams.set('type', filterType);
    url.searchParams.set('ip', filterIP);
    url.searchParams.set('mac', filterMAC);
    url.searchParams.set('sni', filterSNI);

    fetch(url)
      .then(res => res.json())
      .then(data => {
          const tbody = document.getElementById('eventsTable').querySelector('tbody');
          tbody.innerHTML = '';

          data.events.forEach(ev => {
              const tr = document.createElement('tr');
              tr.innerHTML = 
                  '<td>' + ev.timestamp + '</td>' +
                  '<td>' + ev.type + '</td>' +
                  '<td>' + ev.ip + '</td>' +
                  '<td>' + ev.mac + '</td>' +
                  '<td>' + ev.query_sni + '</td>';
              tbody.appendChild(tr);
          });

          totalPages = Math.max(1, Math.ceil(data.total_matches / pageLimit));
          if (data.page > totalPages) {
              currentPage = totalPages;
          }

          liveRowCount = data.events.length;
          updatePageDropdown();
          sendFilterToServer(); // Filter + Live/Seite an WS senden
      })
      .catch(err => {
          console.error('Error loading events:', err);
      });
}

function connectWebSocket() {
    const loc = window.location;
    let protocol = (loc.protocol === 'https:') ? 'wss:' : 'ws:';
    let wsURL = protocol + '//' + loc.host + '/ws';

    socket = new WebSocket(wsURL);

    socket.onopen = () => {
        console.log('WebSocket connected.');
        sendFilterToServer();
    };

    socket.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if (msg.type === 'new') {
            const newEvent = msg.payload;
            const tbody = document.getElementById('eventsTable').querySelector('tbody');

            if (currentPage === totalPages && liveRowCount < pageLimit) {
                // Eintrag direkt anhängen
                const tr = document.createElement('tr');
                tr.innerHTML =
                    '<td>' + newEvent.timestamp + '</td>' +
                    '<td>' + newEvent.type + '</td>' +
                    '<td>' + newEvent.ip + '</td>' +
                    '<td>' + newEvent.mac + '</td>' +
                    '<td>' + newEvent.query_sni + '</td>';
                tbody.appendChild(tr);

                liveRowCount++;
            } else if (liveRowCount >= pageLimit) {
                // Ist die Seite schon voll? Dann „autopaging“
                currentPage++;
                totalPages = currentPage;
                tbody.innerHTML = '';
                liveRowCount = 0;

                console.log('*** Auto-paged to new page:', currentPage);
                updatePageDropdown();
            }
        } else if (msg.type === 'error') {
            alert(msg.payload);
            socket.close();
        }
    };

    socket.onclose = () => {
        console.log('WebSocket closed. Reconnecting in 5 seconds...');
        setTimeout(connectWebSocket, 5000);
    };

    socket.onerror = (error) => {
        console.error('WebSocket error:', error);
    };
}

function sendFilterToServer() {
    if (!socket || socket.readyState !== WebSocket.OPEN) {
        return;
    }
    const msg = {
        type: "setFilter",
        filter: {
            timestamp: filterTimestamp,
            type: filterType,
            ip: filterIP,
            mac: filterMAC,
            sni: filterSNI
        },
        live: isOnLatestPage()
    };
    socket.send(JSON.stringify(msg));
}

// Start/Stop Sniffer
async function startSniffer() {
    const iface = document.getElementById('ifaceSelect').value;
    const url = '/api/start?iface=' + encodeURIComponent(iface);
    const res = await fetch(url);
    if (!res.ok) {
        const errorMsg = await res.text();
        alert('Error starting sniffer: ' + errorMsg);
        return;
    }
    document.getElementById('status').textContent = 'Running';

    const tbody = document.getElementById('eventsTable').querySelector('tbody');
    tbody.innerHTML = '';
    liveRowCount = 0;
    currentPage = 1;
    totalPages = 1;
    updatePageDropdown();
    sendFilterToServer();
    loadEvents();
}

async function stopSniffer() {
    const res = await fetch('/api/stop');
    if (!res.ok) {
        const errorMsg = await res.text();
        alert('Error stopping sniffer: ' + errorMsg);
        return;
    }
    document.getElementById('status').textContent = 'Stopped';
}

// PCAP Upload
async function uploadPCAP() {
    const fileInput = document.getElementById('pcapFile');
    if (!fileInput.files || fileInput.files.length === 0) {
        alert('Please select a PCAP file');
        return;
    }
    const formData = new FormData();
    formData.append('pcapfile', fileInput.files[0]);

    try {
        const res = await fetch('/api/upload', { method: 'POST', body: formData });
        if (!res.ok) {
            const msg = await res.text();
            alert('Error uploading: ' + msg);
            return;
        }
        alert('PCAP file successfully loaded and processed!');
        currentPage = 1;
        loadEvents();
    } catch (err) {
        console.error(err);
        alert('Error uploading: ' + err);
    }
}

// CSV Export (alles)
function exportCSV() {
    window.open('/api/export', '_blank');
}

// CSV Export (nur Filter)
function exportCSVFiltered() {
    const url = new URL('/api/export_filtered', window.location.origin);
    url.searchParams.set('timestamp', filterTimestamp);
    url.searchParams.set('type', filterType);
    url.searchParams.set('ip', filterIP);
    url.searchParams.set('mac', filterMAC);
    url.searchParams.set('sni', filterSNI);

    window.open(url.toString(), '_blank');
}

// Interfaces
async function fetchInterfaces() {
    const res = await fetch('/api/interfaces');
    if (!res.ok) {
        console.error('Could not load interfaces');
        return;
    }
    const data = await res.json();
    const select = document.getElementById('ifaceSelect');
    select.innerHTML = '';
    data.forEach(iface => {
        const opt = document.createElement('option');
        opt.value = iface.Name;
        opt.textContent = iface.Name + (iface.Description ? ' - ' + iface.Description : '');
        select.appendChild(opt);
    });
}

// Initial Setup
document.addEventListener('DOMContentLoaded', () => {
    fetchInterfaces();
    document.getElementById('status').textContent = 'unknown';
    connectWebSocket();
    currentPage = 1;
    totalPages = 1;
    updatePageDropdown();
    loadEvents();
});
</script>
</body>
</html>
`))

var errorTemplate = template.Must(template.New("error").Parse(
    `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"/>
    <title>DNS/TLS Sniffer - Error</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #ffe6e6; display: flex; justify-content: center; align-items: center; height: 100vh; }
        .message { text-align: center; }
        h1 { color: #cc0000; }
    </style>
</head>
<body>
    <div class="message">
        <h1>Connection Denied</h1>
        <p>An active web interface session is already in progress. Please close the other session before opening a new one.</p>
    </div>
</body>
</html>
`))

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------

func main() {
    // Bestehendes Flag für Offline-PCAP:
    pcapFileFlag := flag.String("r", "", "Path to a PCAP file (Offline Mode). If set, live sniffing is disabled.")

    // Neu hinzugefügte Flags:
    noBrowserFlag := flag.Bool("NoBrowser", false, "Disable automatic browser open")
    portFlag := flag.Int("Port", 8089, "Webserver port to listen on")

    // Flags parsen
    flag.Parse()

    checkPrivileges()

    fmt.Println("**********************************************")
    fmt.Println("* DNS over HTTPS Domain Name Sniffer V.8.1.2 *")
    fmt.Println("*             (c) Reto Schaedler             *")
    fmt.Println("**********************************************")
    fmt.Println("")

    if *pcapFileFlag != "" {
        fmt.Printf("Offline Mode. Reading packets from: %s\n", *pcapFileFlag)
        captureMu.Lock()
        processOfflineFile(*pcapFileFlag)
        captureMu.Unlock()
        fmt.Println("Packets processed (Offline).")
        currentPcapFile = *pcapFileFlag
    }

    // Port aus Flag übernehmen:
    port := *portFlag
    // URL für Ausgabe und ggf. Browserstart:
    url := fmt.Sprintf("http://localhost:%d", port)

    // Nur Browser öffnen, wenn Flag NoBrowser NICHT gesetzt ist:
    if !*noBrowserFlag {
        openBrowser(url)
    }

    http.HandleFunc("/", handleIndex)
    http.HandleFunc("/api/interfaces", handleListInterfaces)
    http.HandleFunc("/api/start", handleStart)
    http.HandleFunc("/api/stop", handleStop)
    http.HandleFunc("/api/upload", handleUpload)
    http.HandleFunc("/api/export", handleExport)
    http.HandleFunc("/api/export_filtered", handleExportFiltered)
    http.HandleFunc("/api/events", handleEvents)
    http.HandleFunc("/ws", handleWebSocket)

    fmt.Println("Web interface running at", url)
    log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}

// ----------------------------------------------------------------------------
// Privilege Check
// ----------------------------------------------------------------------------

func checkPrivileges() {
    hasPrivileges = isRootUnix()
    if !hasPrivileges {
        fmt.Println("[WARN] Not running as root/administrator. Some functions may be restricted.")
    }
}

func isRootUnix() bool {
    return os.Geteuid() == 0
}

// ----------------------------------------------------------------------------
// Offline Processing
// ----------------------------------------------------------------------------

func processOfflineFile(path string) {
    log.Printf("[INFO] Processing offline PCAP file: %s\n", path)
    handleOffline, err := pcap.OpenOffline(path)
    if err != nil {
        log.Fatalf("[ERROR] Error opening PCAP file: %v\n", err)
    }
    defer handleOffline.Close()

    clearEventsLocked()

    streamFactory := &tcpStreamFactoryOffline{}
    pool := tcpassembly.NewStreamPool(streamFactory)
    assembler := tcpassembly.NewAssembler(pool)

    packetSource := gopacket.NewPacketSource(handleOffline, handleOffline.LinkType())

    for packet := range packetSource.Packets() {
        if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
            udp := udpLayer.(*layers.UDP)
            if udp.SrcPort == 53 || udp.DstPort == 53 {
                handleDNSPacketOffline(packet, udp.Payload)
            }
            continue
        }
        if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
            if tcp, ok := tcpLayer.(*layers.TCP); ok {
                assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
                setFlowMAC(packet)
            }
        }
    }
    assembler.FlushAll()
    currentPcapFile = path
    log.Printf("[INFO] Completed processing offline PCAP file: %s\n", path)
}

func handleDNSPacketOffline(packet gopacket.Packet, payload []byte) {
    dnsName, isQuery := parseDNS(payload)
    if dnsName != "" && isQuery {
        e := SniffEvent{
            PacketNum: incPacketCounter(),
            Timestamp: packet.Metadata().Timestamp.Format("2006-01-02 15:04:05"),
            Type:      "DNS",
            IP:        getPacketIP(packet),
            MAC:       getPacketMAC(packet),
            QuerySNI:  dnsName,
        }
        addEventOffline(e)
    }
}

// ----------------------------------------------------------------------------
// Live Capture
// ----------------------------------------------------------------------------

func startCapture(iface string) error {
    log.Printf("[INFO] Starting live capture on interface: %s\n", iface)

    // Timeout von 500ms statt pcap.BlockForever
    h, err := pcap.OpenLive(iface, 65535, true, 500*time.Millisecond)
    if err != nil {
        log.Printf("[ERROR] Could not open interface '%s': %v\n", iface, err)
        capturing = false
        return err
    }

    handle = h
    capturing = true
    stopChan = make(chan struct{})
    log.Printf("[INFO] Sniffer started on interface '%s'.\n", iface)

    streamFactory := &tcpStreamFactoryLive{}
    pool := tcpassembly.NewStreamPool(streamFactory)
    assembler := tcpassembly.NewAssembler(pool)

    go func() {
        ticker := time.NewTicker(1 * time.Minute)
        defer ticker.Stop()

        packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
        for {
            select {
            case packet, ok := <-packetSource.Packets():
                if !ok {
                    return
                }
                if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
                    udp := udpLayer.(*layers.UDP)
                    if udp.SrcPort == 53 || udp.DstPort == 53 {
                        handleDNSPacketLive(packet, udp.Payload)
                    }
                    continue
                }
                if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
                    if tcp, ok := tcpLayer.(*layers.TCP); ok {
                        assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
                        setFlowMAC(packet)
                    }
                }
            case <-stopChan:
                return
            case <-ticker.C:
                cutoff := time.Now().Add(-2 * time.Minute)
                assembler.FlushOlderThan(cutoff)
            }
        }
    }()

    return nil
}

func stopCaptureLocked() {
    if !capturing {
        return
    }
    log.Println("[INFO] Stopping sniffer...")

    capturing = false

    if stopChan != nil {
        close(stopChan)
        log.Println("[INFO] stopChan closed")
    }

    if handle != nil {
        log.Println("[INFO] Closing pcap handle...")
        handle.Close() // Handle schließen
        handle = nil
        log.Println("[INFO] pcap handle closed.")
    }

    log.Println("[INFO] Sniffer stopped.")
}


func handleDNSPacketLive(packet gopacket.Packet, payload []byte) {
    dnsName, isQuery := parseDNS(payload)
    if dnsName != "" && isQuery {
        e := SniffEvent{
            PacketNum: incPacketCounter(),
            Timestamp: packet.Metadata().Timestamp.Format("2006-01-02 15:04:05"),
            Type:      "DNS",
            IP:        getPacketIP(packet),
            MAC:       getPacketMAC(packet),
            QuerySNI:  dnsName,
        }
        addEventLive(e)
    }
}

func parseDNS(payload []byte) (string, bool) {
    var msg dns.Msg
    if err := msg.Unpack(payload); err != nil {
        return "", false
    }
    if len(msg.Question) == 0 {
        return "", false
    }
    return msg.Question[0].Name, !msg.Response
}

// ----------------------------------------------------------------------------
// TCP-Reassembly OFFLINE
// ----------------------------------------------------------------------------

type tcpStreamFactoryOffline struct{}

func (f *tcpStreamFactoryOffline) New(netFlow, transportFlow gopacket.Flow) tcpassembly.Stream {
    s := &tcpStreamOffline{
        netFlow:       netFlow,
        transportFlow: transportFlow,
        reader:        tcpreader.NewReaderStream(),
    }
    go s.run()
    return s
}

type tcpStreamOffline struct {
    netFlow       gopacket.Flow
    transportFlow gopacket.Flow
    reader        tcpreader.ReaderStream
    lastTimestamp time.Time
}

func (s *tcpStreamOffline) Reassembled(rs []tcpassembly.Reassembly) {
    for _, r := range rs {
        s.lastTimestamp = r.Seen
    }
    s.reader.Reassembled(rs)
}

func (s *tcpStreamOffline) ReassemblyComplete() {
    s.reader.ReassemblyComplete()
}

func (s *tcpStreamOffline) run() {
    buf := bufio.NewReader(&s.reader)
    srcIP := s.netFlow.Src().String()
    for {
        header, err := readExact(buf, 5)
        if err == io.EOF || err != nil {
            return
        }
        if header[0] == 22 {
            recLen := int(header[3])<<8 | int(header[4])
            payload, err := readExact(buf, recLen)
            if err != nil {
                return
            }
            recordBytes := append(header, payload...)
            sni := extractSNIFromTLSHandshake(recordBytes)
            if sni != "" {
                flowKey := s.netFlow.String()
                flowInfoMu.RLock()
                fi, exists := flowInfoMap[flowKey]
                flowInfoMu.RUnlock()

                mac := "Unknown"
                if exists {
                    mac = fi.MAC
                }
                e := SniffEvent{
                    PacketNum: incPacketCounter(),
                    Timestamp: s.lastTimestamp.Format("2006-01-02 15:04:05"),
                    Type:      "TLS",
                    IP:        srcIP,
                    MAC:       mac,
                    QuerySNI:  sni,
                }
                addEventOffline(e)
            }
        }
    }
}

// ----------------------------------------------------------------------------
// TCP-Reassembly LIVE
// ----------------------------------------------------------------------------

type tcpStreamFactoryLive struct{}

func (f *tcpStreamFactoryLive) New(netFlow, transportFlow gopacket.Flow) tcpassembly.Stream {
    s := &tcpStreamLive{
        netFlow:       netFlow,
        transportFlow: transportFlow,
        reader:        tcpreader.NewReaderStream(),
    }
    go s.run()
    return s
}

type tcpStreamLive struct {
    netFlow       gopacket.Flow
    transportFlow gopacket.Flow
    reader        tcpreader.ReaderStream
    lastTimestamp time.Time
}

func (s *tcpStreamLive) Reassembled(rs []tcpassembly.Reassembly) {
    for _, r := range rs {
        s.lastTimestamp = r.Seen
    }
    s.reader.Reassembled(rs)
}

func (s *tcpStreamLive) ReassemblyComplete() {
    s.reader.ReassemblyComplete()
}

func (s *tcpStreamLive) run() {
    buf := bufio.NewReader(&s.reader)
    srcIP := s.netFlow.Src().String()
    for {
        header, err := readExact(buf, 5)
        if err == io.EOF || err != nil {
            return
        }
        if header[0] == 22 {
            recLen := int(header[3])<<8 | int(header[4])
            payload, err := readExact(buf, recLen)
            if err != nil {
                return
            }
            recordBytes := append(header, payload...)
            sni := extractSNIFromTLSHandshake(recordBytes)
            if sni != "" {
                flowKey := s.netFlow.String()
                flowInfoMu.RLock()
                fi, exists := flowInfoMap[flowKey]
                flowInfoMu.RUnlock()

                mac := "Unknown"
                if exists {
                    mac = fi.MAC
                }
                e := SniffEvent{
                    PacketNum: incPacketCounter(),
                    Timestamp: s.lastTimestamp.Format("2006-01-02 15:04:05"),
                    Type:      "TLS",
                    IP:        srcIP,
                    MAC:       mac,
                    QuerySNI:  sni,
                }
                addEventLive(e)
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Utility-Funktionen
// ----------------------------------------------------------------------------

func incPacketCounter() int {
    packetCounterMu.Lock()
    defer packetCounterMu.Unlock()
    packetCounter++
    return packetCounter
}

func clearEventsLocked() {
    eventsMu.Lock()
    events = []SniffEvent{}
    eventsMu.Unlock()

    packetCounterMu.Lock()
    packetCounter = 0
    packetCounterMu.Unlock()

    flowInfoMu.Lock()
    flowInfoMap = make(map[string]*FlowInfo)
    flowInfoMu.Unlock()

    log.Println("[INFO] Events, counters, and flowInfoMap have been cleared.")
}

func addEventOffline(e SniffEvent) {
    eventsMu.Lock()
    events = append(events, e)
    eventsMu.Unlock()
}

func addEventLive(e SniffEvent) {
    eventsMu.Lock()
    events = append(events, e)
    eventsMu.Unlock()
    broadcastNewEvent(e)
}

func broadcastNewEvent(e SniffEvent) {
    wsClientsMu.Lock()
    conn := currentWSConn
    state := currentClientState
    wsClientsMu.Unlock()

    if conn == nil || state == nil {
        return
    }
    if !state.Live {
        return
    }
    if !matchesFilter(e, state.Filter) {
        return
    }

    msg := wsMessage{Type: "new", Payload: e}
    if err := conn.WriteJSON(msg); err != nil {
        log.Println("[WS] Error writing JSON:", err)
        wsClientsMu.Lock()
        conn.Close()
        currentWSConn = nil
        currentClientState = nil
        wsClientsMu.Unlock()
    }
}

func matchesFilter(e SniffEvent, f EventFilter) bool {
    if f.Timestamp != "" && !strings.Contains(strings.ToLower(e.Timestamp), strings.ToLower(f.Timestamp)) {
        return false
    }
    if f.Type != "" && !strings.Contains(strings.ToLower(e.Type), strings.ToLower(f.Type)) {
        return false
    }
    if f.IP != "" && !strings.Contains(strings.ToLower(e.IP), strings.ToLower(f.IP)) {
        return false
    }
    if f.MAC != "" && !strings.Contains(strings.ToLower(e.MAC), strings.ToLower(f.MAC)) {
        return false
    }
    if f.SNI != "" && !strings.Contains(strings.ToLower(e.QuerySNI), strings.ToLower(f.SNI)) {
        return false
    }
    return true
}

func extractSNIFromTLSHandshake(payload []byte) string {
    if len(payload) < 5 || payload[0] != 22 {
        return ""
    }
    recLen := int(payload[3])<<8 | int(payload[4])
    if len(payload) < 5+recLen {
        return ""
    }
    handshake := payload[5 : 5+recLen]
    if len(handshake) < 4 || handshake[0] != 1 {
        return ""
    }
    totalLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
    if len(handshake) < 4+totalLen {
        return ""
    }
    clientHello := handshake[4 : 4+totalLen]
    if len(clientHello) < 34 {
        return ""
    }
    pos := 34
    sessionIDLen := int(clientHello[pos])
    pos++
    if pos+sessionIDLen > len(clientHello) {
        return ""
    }
    pos += sessionIDLen
    if pos+2 > len(clientHello) {
        return ""
    }
    cipherLen := int(clientHello[pos])<<8 | int(clientHello[pos+1])
    pos += 2 + cipherLen
    if pos >= len(clientHello) {
        return ""
    }
    compLen := int(clientHello[pos])
    pos++
    pos += compLen
    if pos+2 > len(clientHello) {
        return ""
    }
    extensionsLen := int(clientHello[pos])<<8 | int(clientHello[pos+1])
    pos += 2
    if pos+extensionsLen > len(clientHello) {
        return ""
    }
    extensions := clientHello[pos : pos+extensionsLen]
    posExt := 0

    for posExt+4 <= len(extensions) {
        extType := int(extensions[posExt])<<8 | int(extensions[posExt+1])
        extLen := int(extensions[posExt+2])<<8 | int(extensions[posExt+3])
        posExt += 4
        if posExt+extLen > len(extensions) {
            break
        }
        if extType == 0 { // SNI
            if extLen < 2 {
                break
            }
            sniListLen := int(extensions[posExt])<<8 | int(extensions[posExt+1])
            posExt += 2
            if posExt+sniListLen > len(extensions) {
                break
            }
            sniList := extensions[posExt : posExt+sniListLen]
            posExt += sniListLen
            sniPos := 0
            for sniPos+3 <= len(sniList) {
                nameType := sniList[sniPos]
                nameLen := int(sniList[sniPos+1])<<8 | int(sniList[sniPos+2])
                sniPos += 3
                if sniPos+nameLen > len(sniList) {
                    break
                }
                if nameType == 0 {
                    return string(sniList[sniPos : sniPos+nameLen])
                }
                sniPos += nameLen
            }
        } else {
            posExt += extLen
        }
    }
    return ""
}

func getPacketIP(packet gopacket.Packet) string {
    if ip4 := packet.Layer(layers.LayerTypeIPv4); ip4 != nil {
        return ip4.(*layers.IPv4).SrcIP.String()
    }
    if ip6 := packet.Layer(layers.LayerTypeIPv6); ip6 != nil {
        return ip6.(*layers.IPv6).SrcIP.String()
    }
    return ""
}

func getPacketMAC(packet gopacket.Packet) string {
    if eth := packet.Layer(layers.LayerTypeEthernet); eth != nil {
        return eth.(*layers.Ethernet).SrcMAC.String()
    }
    // Loopback
    return "Loopback"
}

func readExact(r *bufio.Reader, n int) ([]byte, error) {
    data := make([]byte, n)
    _, err := io.ReadFull(r, data)
    return data, err
}

func setFlowMAC(packet gopacket.Packet) {
    netFlow := packet.NetworkLayer().NetworkFlow().String()
    reverseFlow := packet.NetworkLayer().NetworkFlow().Reverse().String()
    mac := getPacketMAC(packet)
    flowInfoMu.Lock()
    if _, exists := flowInfoMap[netFlow]; !exists {
        flowInfoMap[netFlow] = &FlowInfo{MAC: mac}
        flowInfoMap[reverseFlow] = &FlowInfo{MAC: mac}
        log.Printf("[FlowInfo] Flow: %s <-> %s, MAC=%s\n", netFlow, reverseFlow, mac)
    }
    flowInfoMu.Unlock()
}

// ----------------------------------------------------------------------------
// HTTP-Handler
// ----------------------------------------------------------------------------

func handleIndex(w http.ResponseWriter, r *http.Request) {
    wsClientsMu.Lock()
    sessionActive := currentWSConn != nil
    wsClientsMu.Unlock()

    if sessionActive {
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        if err := errorTemplate.Execute(w, nil); err != nil {
            http.Error(w, "Error rendering error message: "+err.Error(), http.StatusInternalServerError)
        }
        return
    }

    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    data := struct {
        HasPrivileges bool
    }{
        HasPrivileges: hasPrivileges,
    }
    if err := mainTemplate.Execute(w, data); err != nil {
        http.Error(w, "Error rendering main interface: "+err.Error(), http.StatusInternalServerError)
    }
}





func handleListInterfaces(w http.ResponseWriter, r *http.Request) {
    devices, err := pcap.FindAllDevs()
    if err != nil {
        log.Println("[ERROR] pcap.FindAllDevs:", err)
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Liste der auszuschließenden Wörter
    excludedWords := []string{"bluetooth-monitor", "dbus-session", "dbus-system", "docker", "nflog", "nfqueue"}

    var infos []NetworkInterfaceInfo
    for _, dev := range devices {
        // Überprüfen, ob das Interface ausgeschlossen werden soll
        if isExcluded(dev.Name, excludedWords) {
            continue
        }

        // Prüfen, ob das Interface "up" ist (mit einer der Methoden)
        if isInterfaceUp(dev.Name) || isInterfaceUpSysfs(dev.Name) {
            infos = append(infos, NetworkInterfaceInfo{
                Name:        dev.Name,
                Description: dev.Description,
            })
        }
    }

    // Sortiere alphabetisch
    sort.Slice(infos, func(i, j int) bool {
        return infos[i].Name < infos[j].Name
    })

    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(infos)
}


// Funktion zur Überprüfung, ob ein Interface "up" ist (net.Interfaces Methode)
func isInterfaceUp(name string) bool {
    interfaces, err := net.Interfaces()
    if err != nil {
        log.Printf("[ERROR] net.Interfaces() Fehler: %v\n", err)
        return false
    }
    for _, iface := range interfaces {
        if iface.Name == name && iface.Flags&net.FlagUp != 0 {
            return true
        }
    }
    return false
}


// Alternative Methode zur Überprüfung des Interface-Status (nur Linux)
func isInterfaceUpSysfs(name string) bool {
    statusPath := fmt.Sprintf("/sys/class/net/%s/operstate", name)
    data, err := ioutil.ReadFile(statusPath)
    if err != nil {
        log.Printf("[ERROR] Lesen von %s fehlgeschlagen: %v\n", statusPath, err)
        return false
    }
    status := strings.TrimSpace(string(data))
    return status == "up"
}



// Funktion zum Überprüfen, ob ein Interface ausgeschlossen werden soll
func isExcluded(name string, excludedWords []string) bool {
    for _, word := range excludedWords {
        if strings.Contains(name, word) {
            return true
        }
    }
    return false
}










func handleStart(w http.ResponseWriter, r *http.Request) {
    iface := r.URL.Query().Get("iface")

    captureMu.Lock()
    defer captureMu.Unlock()

    if capturing {
        stopCaptureLocked()
    }
    if uploadedPcapFile != "" {
        _ = os.Remove(uploadedPcapFile)
        uploadedPcapFile = ""
        currentPcapFile = ""
    }
    clearEventsLocked()

    // startCapture gibt jetzt einen Fehler zurück, wenn das Interface nicht geöffnet werden kann
    if err := startCapture(iface); err != nil {
        http.Error(w, "Failed to open interface: "+err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
}

func handleStop(w http.ResponseWriter, r *http.Request) {
    captureMu.Lock()
    defer captureMu.Unlock()

    stopCaptureLocked()
    w.WriteHeader(http.StatusOK)
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
        return
    }
    captureMu.Lock()
    defer captureMu.Unlock()

    if capturing {
        stopCaptureLocked()
    }
    if uploadedPcapFile != "" {
        _ = os.Remove(uploadedPcapFile)
        uploadedPcapFile = ""
        currentPcapFile = ""
    }

    err := r.ParseMultipartForm(50 << 20) // 50 MB
    if err != nil {
        http.Error(w, "Error parsing multipart form: "+err.Error(), http.StatusBadRequest)
        return
    }
    file, handler, err := r.FormFile("pcapfile")
    if err != nil {
        http.Error(w, "Error reading file: "+err.Error(), http.StatusBadRequest)
        return
    }
    defer file.Close()

    tempDir := os.TempDir()
    tempFileName := fmt.Sprintf("upload_%d_%s", time.Now().UnixNano(), filepath.Base(handler.Filename))
    tempPath := filepath.Join(tempDir, tempFileName)

    out, err := os.Create(tempPath)
    if err != nil {
        http.Error(w, "Error creating temp file: "+err.Error(), http.StatusInternalServerError)
        return
    }
    defer out.Close()

    _, err = io.Copy(out, file)
    if err != nil {
        http.Error(w, "Error writing temp file: "+err.Error(), http.StatusInternalServerError)
        return
    }

    uploadedPcapFile = tempPath
    currentPcapFile = tempPath

    log.Printf("[INFO] PCAP file saved to %s. Now processing offline...\n", tempPath)
    processOfflineFile(tempPath)
    w.WriteHeader(http.StatusOK)
}

func handleExport(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/csv; charset=utf-8")
    w.Header().Set("Content-Disposition", `attachment; filename="sniff_export_all.csv"`)
    writer := csv.NewWriter(w)
    defer writer.Flush()

    writer.Write([]string{"Timestamp", "Type", "IP", "MAC", "QuerySNI"})

    eventsMu.RLock()
    defer eventsMu.RUnlock()

    for _, ev := range events {
        writer.Write([]string{
            ev.Timestamp,
            ev.Type,
            ev.IP,
            ev.MAC,
            ev.QuerySNI,
        })
    }
}

func handleExportFiltered(w http.ResponseWriter, r *http.Request) {
    tsFilter := r.URL.Query().Get("timestamp")
    typeFilter := r.URL.Query().Get("type")
    ipFilter := r.URL.Query().Get("ip")
    macFilter := r.URL.Query().Get("mac")
    sniFilter := r.URL.Query().Get("sni")

    f := EventFilter{
        Timestamp: tsFilter,
        Type:      typeFilter,
        IP:        ipFilter,
        MAC:       macFilter,
        SNI:       sniFilter,
    }

    eventsMu.RLock()
    defer eventsMu.RUnlock()

    var filtered []SniffEvent
    for _, e := range events {
        if matchesFilter(e, f) {
            filtered = append(filtered, e)
        }
    }
    //totalMatches := len(filtered)

    w.Header().Set("Content-Type", "text/csv; charset=utf-8")
    w.Header().Set("Content-Disposition", `attachment; filename="sniff_export_filtered.csv"`)
    writer := csv.NewWriter(w)
    defer writer.Flush()

    writer.Write([]string{"Timestamp", "Type", "IP", "MAC", "QuerySNI"})

    for _, ev := range filtered {
        writer.Write([]string{
            ev.Timestamp,
            ev.Type,
            ev.IP,
            ev.MAC,
            ev.QuerySNI,
        })
    }
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
    pageStr := r.URL.Query().Get("page")
    limitStr := r.URL.Query().Get("limit")
    tsFilter := r.URL.Query().Get("timestamp")
    typeFilter := r.URL.Query().Get("type")
    ipFilter := r.URL.Query().Get("ip")
    macFilter := r.URL.Query().Get("mac")
    sniFilter := r.URL.Query().Get("sni")

    page, _ := strconv.Atoi(pageStr)
    if page < 1 {
        page = 1
    }
    limit, _ := strconv.Atoi(limitStr)
    if limit <= 0 {
        limit = 2500
    }

    f := EventFilter{
        Timestamp: tsFilter,
        Type:      typeFilter,
        IP:        ipFilter,
        MAC:       macFilter,
        SNI:       sniFilter,
    }

    eventsMu.RLock()
    defer eventsMu.RUnlock()

    var filtered []SniffEvent
    for _, e := range events {
        if matchesFilter(e, f) {
            filtered = append(filtered, e)
        }
    }
    totalMatches := len(filtered)

    startIdx := (page - 1) * limit
    if startIdx > totalMatches {
        startIdx = totalMatches
    }
    endIdx := startIdx + limit
    if endIdx > totalMatches {
        endIdx = totalMatches
    }
    pageSlice := filtered[startIdx:endIdx]

    resp := PagedEventsResponse{
        Events:       pageSlice,
        TotalMatches: totalMatches,
        Page:         page,
        Limit:        limit,
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(resp)
}

var upgrader = websocket.Upgrader{
    CheckOrigin: func(r *http.Request) bool { return true },
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
    wsClientsMu.Lock()
    defer wsClientsMu.Unlock()

    if currentWSConn != nil {
        conn, err := upgrader.Upgrade(w, r, nil)
        if err != nil {
            log.Println("[WS] Upgrade error:", err)
            return
        }
        errorMsg := wsMessage{
            Type:    "error",
            Payload: "Only one web interface session is allowed at a time.",
        }
        conn.WriteJSON(errorMsg)
        conn.Close()
        log.Println("[WS] Rejected a client connection. Only one client allowed.")
        return
    }

    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Println("[WS] Upgrade error:", err)
        return
    }
    currentWSConn = conn
    currentClientState = &ClientState{
        Filter: EventFilter{},
        Live:   false,
    }
    log.Println("[WS] New client connected.")

    go func() {
        defer func() {
            wsClientsMu.Lock()
            currentWSConn = nil
            currentClientState = nil
            wsClientsMu.Unlock()
            conn.Close()
            log.Println("[WS] Client disconnected.")
        }()
        for {
            _, data, err := conn.ReadMessage()
            if err != nil {
                return
            }
            var fm FilterMessage
            if err := json.Unmarshal(data, &fm); err != nil {
                continue
            }
            if fm.Type == "setFilter" {
                wsClientsMu.Lock()
                if currentClientState != nil {
                    currentClientState.Filter = fm.Filter
                    currentClientState.Live = fm.Live
                }
                wsClientsMu.Unlock()
            }
        }
    }()
}

// ----------------------------------------------------------------------------
// openBrowser
// ----------------------------------------------------------------------------

func openBrowser(url string) {
    var err error
    switch runtime.GOOS {
    case "windows":
        err = exec.Command("cmd", "/c", "start", url).Start()
    case "darwin":
        err = exec.Command("open", url).Start()
    case "linux":
        err = exec.Command("xdg-open", url).Start()
    default:
        fmt.Printf("[WARN] Unsupported platform: %s\n", runtime.GOOS)
    }
    if err != nil {
        fmt.Printf("[WARN] Could not open browser automatically: %v\n", err)
    }
}
