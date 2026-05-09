using System.IO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Xml;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography.Xml;
using Newtonsoft.Json;

namespace ConexionDGII
{
    public class FacturacionElectronicaDGII
    {
        private static readonly HttpClient _httpClient = new HttpClient();
        private static string _tokenGlobal;
        private static string _trackIdGlobal;
        private static string _eNCFGlobal;
        private static string _RNCEmisorGlobal;
        private static string _eNCFGlobalAC;
        private static string _RNCEmisorGlobalAC;

        private static string _XMLSemilla;
        private static string _XMLSemillaFirmada;
        private static string _XMLFactura;
        private static string _XMLFacturaFirmada;
        private static string _CodigoSeguridad;

        private static string thumbprint2026 = "5F5017E1810EBEAF9DAE0AD482C252F4AC19CA91";

        public static string EnviarTokenSincrona(string urlSemilla, string passCert, string jsonInvoiceFO)
        {
            return ObtenerSemilla(urlSemilla, passCert, jsonInvoiceFO).GetAwaiter().GetResult();
        }

        private static X509Certificate2 GetCertificateFromWINDOWS(string thumbprint)
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);

                X509Certificate2Collection certCollection = store.Certificates.Find(
                    X509FindType.FindByThumbprint,
                    thumbprint,
                    validOnly: false);

                X509Certificate2 cert = certCollection.OfType<X509Certificate2>().FirstOrDefault();

                if (cert == null)
                {
                    throw new Exception(
                        $"❌ Certificado no encontrado. " +
                        $"Thumbprint buscado: {thumbprint}. " +
                        $"StoreName: {store.Name}, StoreLocation: {store.Location}, " +
                        $"Total certificados en el store: {store.Certificates.Count}."
                    );
                }
                return cert;
            }
        }

        public static List<CertCheckResult> ListAllCertificates()
        {
            var results = new List<CertCheckResult>();

            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);

                foreach (var cert in store.Certificates.OfType<X509Certificate2>())
                {
                    results.Add(new CertCheckResult
                    {
                        Existe = true,
                        Mensaje = $"Certificado encontrado",
                        Subject = cert.Subject,
                        Thumbprint = cert.Thumbprint
                    });
                }
            }

            return results;
        }

        public class CertCheckResult
        {
            public bool Existe { get; set; }
            public string Mensaje { get; set; }
            public string Subject { get; set; }
            public string Thumbprint { get; set; }
        }

        public static CertCheckResult GetCertificateFromStoreWINDOWS2(string thumbprint)
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);

                var certs = store.Certificates.Find(
                    X509FindType.FindByThumbprint,
                    thumbprint,
                    validOnly: false);

                if (certs.Count > 0)
                {
                    var cert = certs[0];
                    return new CertCheckResult
                    {
                        Existe = true,
                        Mensaje = "✅ Certificado encontrado",
                        Subject = cert.Subject,
                        Thumbprint = cert.Thumbprint
                    };
                }
                else
                {
                    return new CertCheckResult
                    {
                        Existe = false,
                        Mensaje = $"❌ No se encontró el certificado con Thumbprint: {thumbprint}. " +
                                  $"StoreName: My, StoreLocation: CurrentUser. " +
                                  $"Total certificados en el store: {store.Certificates.Count}",
                        Subject = null,
                        Thumbprint = thumbprint
                    };
                }
            }
        }

        public static async Task<string> ObtenerSemilla(string urlSemilla, string passCert, string jsonInvoiceFO)
        {
            using (HttpClient client = new HttpClient())
            {
                HttpResponseMessage response = await client.GetAsync(urlSemilla);
                string responseBody = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    string xmlSemilla = await response.Content.ReadAsStringAsync();

                    _XMLSemilla = xmlSemilla;

                    string JsonEnviado = await FirmarSemilla(passCert, jsonInvoiceFO);

                    var resultado = new
                    {
                        json = JsonEnviado,
                        encf = _eNCFGlobal,
                        xmlsemilla = _XMLSemilla,
                        xmlsemillafirmada = _XMLSemillaFirmada,
                        token = _tokenGlobal, 
                        xmlfactura = _XMLFactura,
                        xmlfacturafirmada = _XMLFacturaFirmada,
                        codigoseguridad = _CodigoSeguridad
                    };

                    string jsonString = JsonConvert.SerializeObject(resultado);

                    return jsonString;
                }
                else
                {
                    Console.WriteLine($"Error al obtener el XML Código: {response.StatusCode}");
                    return $"Error: {response.StatusCode} - {responseBody}";
                }
            }
        }

        public static async Task<string> FirmarSemilla(string passCert, string jsonInvoiceFO)
        {

            try
            {

                XmlDocument xmlDoc = new XmlDocument();

                xmlDoc.LoadXml(_XMLSemilla);

                SignXmlSeed(xmlDoc, thumbprint2026, passCert);

                string xmlSemillaFirmada = xmlDoc.OuterXml;
                _XMLSemillaFirmada = xmlSemillaFirmada;

                Console.WriteLine(_XMLSemillaFirmada);

                JObject jsonObj = JObject.Parse(jsonInvoiceFO);

                _eNCFGlobal = jsonObj["ECF"]["Encabezado"]["IdDoc"]["eNCF"]?.ToString();
                _RNCEmisorGlobal = jsonObj["ECF"]["Encabezado"]["Emisor"]["RNCEmisor"]?.ToString();

                XmlDocument xmlDocument = JsonConvert.DeserializeXmlNode(jsonInvoiceFO);

                XmlDeclaration xmlDeclaration = xmlDocument.CreateXmlDeclaration("1.0", "utf-8", null);
                XmlElement root = xmlDocument.DocumentElement;
                xmlDocument.InsertBefore(xmlDeclaration, root);

                string xmlFactura = xmlDocument.OuterXml;
                _XMLFactura = xmlFactura;

                string xmlFacturaFirmada = await FirmarFactura(passCert);

                return jsonInvoiceFO; 

            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
                return $"Error: {ex.Message}"; 

            }
        }

        public static async Task<string> FirmarFactura(string passCert)
        {

            try
            {

                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.LoadXml(_XMLFactura);

                SignXmlInvoice(xmlDoc, thumbprint2026, passCert);

                string xmlFacturaFirmada = xmlDoc.OuterXml;

                XmlDocument xmlDoc2 = new XmlDocument();
                xmlDoc2.PreserveWhitespace = true;
                xmlDoc2.LoadXml(xmlFacturaFirmada);

                GetSignatureValueFromSignedXml(xmlDoc2);

                _XMLFacturaFirmada = xmlFacturaFirmada;

                Console.WriteLine(_XMLFacturaFirmada);

                return xmlFacturaFirmada;

            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
                return $"Error: {ex.Message}"; 
            }
        }

        public static string GetSignatureValueFromSignedXml(XmlDocument signedXmlDoc2)
        {
            XmlNamespaceManager nsManager = new XmlNamespaceManager(signedXmlDoc2.NameTable);
            nsManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

            XmlNode signatureValueNode = signedXmlDoc2.SelectSingleNode("//ds:SignatureValue", nsManager);

            if (signatureValueNode != null)
            {
                string fullSignatureValue = signatureValueNode.InnerText;

                if (fullSignatureValue.Length >= 6)
                {
                    _CodigoSeguridad = fullSignatureValue.Substring(0, 6);
                }
                else
                {
                    throw new Exception("El valor de SignatureValue tiene menos de 6 caracteres.");
                }

                return _CodigoSeguridad;

            }
            else
            {
                throw new Exception("El nodo SignatureValue no se encontró en el XML.");
            }
        }

        static XmlDocument SignXmlInvoice(XmlDocument xmlDoc, string thumprint2026, string passCert)
        {
            var cert = GetCertificateFromWINDOWS(thumprint2026);

            if (cert.PrivateKey == null)
                throw new Exception("El certificado no contiene una clave privada.");

            var key = cert.GetRSAPrivateKey();

            if (key == null)
                throw new Exception("No se pudo obtener la clave privada RSA del certificado.");

            var signedXml = new SignedXml(xmlDoc)
            {
                SigningKey = key
            };

            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;

            var reference = new Reference
            {
                Uri = "",
                DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256"
            };

            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            signedXml.AddReference(reference);

            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(cert));
            signedXml.KeyInfo = keyInfo;

            signedXml.ComputeSignature();

            XmlElement xmlFirmaDigital = signedXml.GetXml();
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlFirmaDigital, true));

            return xmlDoc;
        }

        static XmlDocument SignXmlSeed(XmlDocument xmlDoc, string thumprint2026, string passCert)
        {
            if (string.IsNullOrEmpty(passCert))
                throw new ArgumentException("La contraseña del certificado no puede ser nula o vacía.", nameof(passCert));

            var cert = GetCertificateFromWINDOWS(thumprint2026);

            if (cert.PrivateKey == null)
                throw new Exception("El certificado no contiene una clave privada.");

            var key = cert.GetRSAPrivateKey();

            if (key == null)
                throw new Exception("No se pudo obtener la clave privada RSA del certificado.");

            var signedXml = new SignedXml(xmlDoc)
            {
                SigningKey = key
            };

            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;

            var reference = new Reference
            {
                Uri = "",
                DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256"
            };

            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            signedXml.AddReference(reference);

            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(cert));
            signedXml.KeyInfo = keyInfo;

            signedXml.ComputeSignature();

            XmlElement xmlFirmaDigital = signedXml.GetXml();
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlFirmaDigital, true));

            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] firmaBytes = Encoding.UTF8.GetBytes(xmlFirmaDigital.OuterXml);
                byte[] hashBytes = sha256.ComputeHash(firmaBytes);

                string hashHex = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

                string codigoSeguridad = hashHex.Substring(0, 6);

                XmlNode nodoCodigoSeguridad = xmlDoc.SelectSingleNode("//CodigoSeguridadeCF");
                if (nodoCodigoSeguridad != null)
                {
                    nodoCodigoSeguridad.InnerText = codigoSeguridad;
                }
            }

            return xmlDoc;
        }

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        public static string EnviarFacturaElectronicaSincrona(string urlValidarSemilla, string urlRecepcionFactura, string urlConsultaFactura)
        {
            return ValidarSemilla(urlValidarSemilla, urlRecepcionFactura, urlConsultaFactura).GetAwaiter().GetResult();
        }

        public static async Task<string> ValidarSemilla(string urlValidarSemilla, string urlRecepcionFactura, string urlConsultaFactura)
        {

            string fileName = "semillaFirmada.xml"; 

            try
            {
                using (HttpClient client = new HttpClient())
                {
                    using (var form = new MultipartFormDataContent())
                    {
                        var fileContent = new ByteArrayContent(Encoding.UTF8.GetBytes(_XMLSemillaFirmada));
                        fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("text/xml");

                        form.Add(fileContent, "xml", Path.GetFileName(fileName));

                        client.DefaultRequestHeaders.Add("accept", "application/json");

                        HttpResponseMessage response = await client.PostAsync(urlValidarSemilla, form);
                        string responseBody = await response.Content.ReadAsStringAsync();

                        if (response.IsSuccessStatusCode)
                        {
                            Console.WriteLine(responseBody);

                            var json = JObject.Parse(responseBody);
                            _tokenGlobal = json["token"]?.ToString();

                            string JsonFinal = await EnviarFacturaElectronica(urlRecepcionFactura, urlConsultaFactura);
                            return JsonFinal;

                        }
                        else
                        {
                            Console.WriteLine(response.StatusCode);
                            Console.WriteLine(responseBody);
                            return $"Error: {response.StatusCode} - {responseBody}";
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($" Error: {ex.Message}");
                return $" Error: {ex.Message}";

            }
        }

        public static async Task<string> EnviarFacturaElectronica(string urlRecepcionFactura, string urlConsultaFactura)
        {

            string xmlPath = $"{_RNCEmisorGlobal}{_eNCFGlobal}.xml"; 

            try
            {

                using (HttpClient client = new HttpClient())
                {
                    client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _tokenGlobal);
                    client.DefaultRequestHeaders.Add("accept", "application/json");

                    using (var form = new MultipartFormDataContent())
                    {
                        byte[] xmlBytes = Encoding.UTF8.GetBytes(_XMLFacturaFirmada);

                        var fileContent = new ByteArrayContent(xmlBytes);
                        fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("text/xml");

                        form.Add(fileContent, "xml", Path.GetFileName(xmlPath));

                        HttpResponseMessage response = await client.PostAsync(urlRecepcionFactura, form);
                        string responseBody = await response.Content.ReadAsStringAsync();

                        if (response.IsSuccessStatusCode)
                        {
                            Console.WriteLine(responseBody);

                            var json = JObject.Parse(responseBody);
                            _trackIdGlobal = json["trackId"]?.ToString();

                            string estadoFacturaJson = await ConsultarEstadoFacturaElectronica(urlConsultaFactura);
                            return estadoFacturaJson;

                        }
                        else
                        {
                            Console.WriteLine(response.StatusCode);
                            Console.WriteLine(responseBody);

                            return $"Error: {response.StatusCode} - {responseBody}";

                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($" Error: {ex.Message}");
                return $" Error: {ex.Message}";

            }
        }

        public static async Task<string> ConsultarEstadoFacturaElectronica(string urlConsultaFactura)
        {
            string url = $"{urlConsultaFactura}?TrackId={_trackIdGlobal}";

            try
            {
                using (HttpClient client = new HttpClient())
                {
                    client.DefaultRequestHeaders.Add("accept", "application/json");
                    client.DefaultRequestHeaders.Add("Authorization", $"Bearer {_tokenGlobal}");

                    HttpResponseMessage response = await client.GetAsync(url);
                    string responseBody = await response.Content.ReadAsStringAsync();

                    if (response.IsSuccessStatusCode)
                    {
                        Console.WriteLine(responseBody);

                        var json = JObject.Parse(responseBody);

                        return responseBody;

                    }
                    else
                    {
                        Console.WriteLine(response.StatusCode);
                        Console.WriteLine(responseBody);

                        return $"Error: {response.StatusCode} - {responseBody}";
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($" Error: {ex.Message}");
                return $" Error: {ex.Message}";

            }
        }

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        public static async Task<string> FirmarAprobacionComercial(string passCert)
        {
            string xmlPath = "C:\\Users\\andersonmgordilloh\\source\\repos\\FacturacionElectronicaDGII\\ArchivosDGII\\aprobacioncomercial.xml";  // Ruta donde tienes tu semilla
            string signedXmlPath = $"C:\\Users\\andersonmgordilloh\\source\\repos\\FacturacionElectronicaDGII\\ArchivosDGII\\{_RNCEmisorGlobalAC}{_eNCFGlobalAC}.xml"; // Archivo firmado
            //string pathCert = "C:\\Users\\andersonmgordilloh\\source\\repos\\FacturacionElectronicaDGII\\ArchivosDGII\\20250130-2113054-YAD25P5MJ.p12"; // Ruta de tu certificado

            string invoice;

            try
            {
                // X509Certificate2 cert = new X509Certificate2(pathCert, passCert, X509KeyStorageFlags.Exportable);

                XmlDocument xmlDoc = new XmlDocument();
                //xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(xmlPath);

                //SignXmlRepo(xmlDoc, pathCert, passCert);


                SignXmlSeed(xmlDoc, thumbprint2026, passCert);


                // Guardar el XML firmado
                xmlDoc.Save(signedXmlPath);
                Console.WriteLine("XML firmado y guardado en: " + signedXmlPath);

                invoice = "Aprobacion Comercial Firmada";
                return invoice;

            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
                return $"Error: {ex.Message}";
            }
        }

        public static async Task RecepcionAprobacionComercial(string passCert)
        {
            string urlRecepcionFactura = "https://ecf.dgii.gov.do/certecf/AprobacionComercial/api/AprobacionComercial";

            string jsonPathAC = "C:\\Users\\andersonmgordilloh\\source\\repos\\FacturacionElectronicaDGII\\ArchivosDGII\\aprobacioncomercial.json"; // Ruta del JSON
            string filePathAC = "C:\\Users\\andersonmgordilloh\\source\\repos\\FacturacionElectronicaDGII\\ArchivosDGII\\aprobacioncomercial.xml"; // Ruta donde guardar el archivo

            string xmlPath = $"C:\\Users\\andersonmgordilloh\\source\\repos\\FacturacionElectronicaDGII\\ArchivosDGII\\{_RNCEmisorGlobalAC}{_eNCFGlobalAC}.xml"; // Ruta del XML

            try
            {
                ////////////////////////////////////////////////////Leer el archivo de Aprobacion Comercial JSON a XML///////////////////////////////////////////////////////////////////////////

                string jsonContentAC = File.ReadAllText(jsonPathAC);

                JObject jsonObjAC = JObject.Parse(jsonContentAC); // Convertir JSON a JObject

                _eNCFGlobalAC = jsonObjAC["ACECF"]["DetalleAprobacionComercial"]["eNCF"]?.ToString();
                _RNCEmisorGlobalAC = jsonObjAC["ACECF"]["DetalleAprobacionComercial"]["RNCEmisor"]?.ToString();

                XmlDocument xmlDocumentAC = JsonConvert.DeserializeXmlNode(jsonContentAC);

                // Agregar la declaración XML estándar
                XmlDeclaration xmlDeclarationAC = xmlDocumentAC.CreateXmlDeclaration("1.0", "utf-8", null);
                XmlElement rootAC = xmlDocumentAC.DocumentElement;
                xmlDocumentAC.InsertBefore(xmlDeclarationAC, rootAC);

                // Guardar el XML en un archivo con la declaración XML
                using (XmlWriter writer = XmlWriter.Create(filePathAC, new XmlWriterSettings { Indent = true, Encoding = System.Text.Encoding.UTF8 }))
                {
                    xmlDocumentAC.WriteTo(writer);
                }

                await FirmarAprobacionComercial(passCert);

                ////////////////////////////////////////////////////Leer el archivo de Aprobacion Comercial JSON a XML///////////////////////////////////////////////////////////////////////////

                using (HttpClient client = new HttpClient())
                {
                    // Agregar el token de autorización
                    client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", _tokenGlobal);
                    client.DefaultRequestHeaders.Add("accept", "application/json");

                    // Crear el contenido multipart/form-data
                    using (var form = new MultipartFormDataContent())
                    {
                        // Leer el archivo XML
                        var fileContent = new ByteArrayContent(File.ReadAllBytes(xmlPath));
                        fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("text/xml");

                        // Agregar el archivo al formulario
                        form.Add(fileContent, "xml", Path.GetFileName(xmlPath));

                        // Enviar la solicitud POST
                        HttpResponseMessage response = await client.PostAsync(urlRecepcionFactura, form);
                        string responseBody = await response.Content.ReadAsStringAsync();

                        if (response.IsSuccessStatusCode)
                        {
                            Console.WriteLine(responseBody);

                            var json = JObject.Parse(responseBody);
                        }
                        else
                        {
                            Console.WriteLine(response.StatusCode);
                            Console.WriteLine(responseBody);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($" Error: {ex.Message}");

            }
        }

    }

}
