from xml.dom import minidom
import shlex, subprocess

doc = minidom.parse('C:\\Users\\FMAG\\allPorts.xml')

#Lineas de report
report = []

resultadoPorIP = ['0']
dispositivos= doc.getElementsByTagName("host")

contador = 0

#Función que ejecuta el segundo escaneo por equipo pasando como parámetro la ip y los puertos abiertos
#Devuelve el resultado en xml
def runSecondNMAP(ip, ports):
	command_line1 = 'nmap -sC -sV -p'
	command_line2 = ports + " " + ip
	command = command_line1 + command_line2
	#return command
	args = shlex.split(command)
	string1 = subprocess.call(args)
	return string1

#Procesamos el XML obtenido para cada uno de los equipos y lo guardamos como una línea en el report.
def insertLine(reportLine):
	line = reportLine()

	for resultado in resultadoPorIP:
		line.ip = resultado.getElementsByTagName("address")
		line.mac = ""
		puertos = resultado.getElementsByTagName("ports")
		for p in puertos:
			p1 = port()
			port.id = p.getAttribute("portid")

	report.append(reportLine)


#Ejecuta por cada uno de los dispositivos de la lista un escaneo más profundo y guarda el resultado con formato XML en una lista.
for dispositivo in dispositivos:
	
	contador = contador + 1 #Número de equipo descubierto
	addresses = dispositivo.getElementsByTagName("address") #Direcciones del host
	print("Dispositivo encontrado: " + str(contador))
	for address in addresses:
		
		if address.getAttribute("addrtype") == "ipv4":
			print("Address:%s " % address.getAttribute("addr"))
			direccionIP = address.getAttribute("addr")
		elif address.getAttribute("addrtype") == "mac":
			print("Mac:%s " % address.getAttribute("addr"))
			#Aqui vamos mostrar todos los puertos que se han encontrado abiertos.
			puertos = dispositivo.getElementsByTagName("port")
			puertos_array = ['0'] #Puertos en string para que ejecutar la segunda parte del escaneo
			for puerto in puertos:
				numeroPuerto = puerto.getAttribute("portid")
				puertos_array.append(numeroPuerto)
			resultadoPorIP.append(runSecondNMAP(direccionIP, ",".join(puertos_array)))
			print(resultadoPorIP)

insertLine()

class reportLine():
	ip = ""
	mac = ""
	ports = []

class port():
	id = ""
	name = ""
	protocol = ""
	state = ""
	reason = ""
	reason_ttl = ""
	url = ""
	extraInfo = ""