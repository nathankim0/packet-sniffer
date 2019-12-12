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
<src img="https://user-images.githubusercontent.com/37360089/70723397-2e48fd00-1d3c-11ea-8dda-61f65e3deee9.png"></img>
<src img="https://user-images.githubusercontent.com/37360089/70723479-4d478f00-1d3c-11ea-9fd0-32041a00e0ba.png"></img>
<src img="https://user-images.githubusercontent.com/37360089/70723506-589aba80-1d3c-11ea-9698-aac110655e89.png"></img>
  </div>
  
추가기능 출력화면
--
# HTTP
<div>
<src img="https://user-images.githubusercontent.com/37360089/70723605-7e27c400-1d3c-11ea-8bb5-2659565deb38.png"></img>
80번, 443번 source port, destination port 인 경우 HTTP 프로토콜
  <src img="https://user-images.githubusercontent.com/37360089/70723659-9a2b6580-1d3c-11ea-95b8-7a9c58e4b6ad.png"></img>
   request와 respones시 http 헤더       정보가 다른 것을 확인할 수 있다.
  </div>
  

