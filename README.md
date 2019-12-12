# packet_sniffer

기본기능
--
Application Layer<br>  
	HTTP, DNS, P2P 각각을 구분하여 필터링 제공

Transport Layer(TCP / UDP)<br>
	Source Port, Destination Port: 포트번호 제공<br>
	TCP : Sequence number, Acknowledgment number 제공

Network Layer<br>
	Source IP, Destination IP 제공

+패킷 길이, Source MAC address, Destination MAC address, EtherType, Header 길이, TTL

기본기능 출력화면
--
<div>

<img src="https://user-images.githubusercontent.com/37360089/70724357-ce535600-1d3d-11ea-96c2-1b99771d1988.png"></img>

<img src="https://user-images.githubusercontent.com/37360089/70724391-dc08db80-1d3d-11ea-90aa-e28e8c804f2e.png"></img>

<img src="https://user-images.githubusercontent.com/37360089/70724401-e4611680-1d3d-11ea-896f-13df04daeafa.png"></img>

</div>
  
HTTP 출력화면
--
포트번호가 80 -> http, 443 -> https 
<div>
	<img src="https://user-images.githubusercontent.com/37360089/70724568-2ee29300-1d3e-11ea-822a-01a2b4466149.png"></img>

<img src="https://user-images.githubusercontent.com/37360089/70724588-34d87400-1d3e-11ea-9cfd-99184eda7dcf.png"></img>

</div>

P2P 출력화면
--
torrent 사용, ip 주소로 확인
<div>
	<img src="https://user-images.githubusercontent.com/37360089/70724854-b4664300-1d3e-11ea-8112-28baa5947a1f.png"></img>
	<img src="https://user-images.githubusercontent.com/37360089/70725028-05763700-1d3f-11ea-88f4-906ee42582e0.png"></img>
</div>

DNS 출력화면
--

FTP 출력화면
--


