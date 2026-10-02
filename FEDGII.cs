using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;

namespace ConexionDGII
{
    public class FacturacionElectronicaDGII
    {
        private static readonly HttpClient _httpClient = new HttpClient();
        private static string _tokenGlobal;
        private static string _trackIdGlobal;
        private static string _eNCFGlobal;
        private static string _RNCEmisorGlobal;
        private static string _Root;
        private static string _eNCFGlobalAC;
        private static string _RNCEmisorGlobalAC;

        private static string _XMLSemilla;
        private static string _XMLSemillaFirmada;
        private static string _XMLFactura;
        private static string _XMLFacturaFirmada;
        private static string _CodigoSeguridad = "";

        private static string thumbprint2026 = "5F5017E1810EBEAF9DAE0AD482C252F4AC19CA91";

        /// <summary>
        /// Obtiene únicamente el contenido XML de la Semilla desde la URL de la DGII.
        /// </summary>
        public static async Task<string> ObtenerSemillaXmlAsync(string urlSemilla, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(urlSemilla))
            {
                throw new ArgumentNullException(nameof(urlSemilla), "La URL de la semilla no puede estar vacía.");
            }

            using (var request = new HttpRequestMessage(HttpMethod.Get, urlSemilla))
            {
                using (var response = await _httpClient.SendAsync(request, cancellationToken))
                {
                    string responseBody = await response.Content.ReadAsStringAsync();

                    if (!response.IsSuccessStatusCode)
                    {
                        throw new HttpRequestException($"Error al consumir la Semilla DGII. Código HTTP: {response.StatusCode}. Respuesta: {responseBody}");
                    }

                    return responseBody;
                }
            }
        }

        public static async Task<string> ValidarCertificadoXmlAsync(string urlValidacion, string xmlSemillaFirmada, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(urlValidacion))
            {
                throw new ArgumentNullException(nameof(urlValidacion), "La URL de validación no puede estar vacía.");
            }

            if (string.IsNullOrWhiteSpace(xmlSemillaFirmada))
            {
                throw new ArgumentException("El contenido del XML firmado es requerido.", nameof(xmlSemillaFirmada));
            }

            string fileName = "semillaFirmada.xml";

            try
            {
                using (HttpClient client = new HttpClient())
                {
                    using (var form = new MultipartFormDataContent())
                    {
                        var fileContent = new ByteArrayContent(Encoding.UTF8.GetBytes(xmlSemillaFirmada));
                        fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("text/xml");

                        form.Add(fileContent, "xml", Path.GetFileName(fileName));

                        client.DefaultRequestHeaders.Add("accept", "application/json");

                        HttpResponseMessage response = await client.PostAsync(urlValidacion, form);
                        string responseBody = await response.Content.ReadAsStringAsync();

                        if (!response.IsSuccessStatusCode)
                        {
                            throw new HttpRequestException($"Error al validar certificado en DGII. Código HTTP: {response.StatusCode}. Respuesta: {responseBody}");
                        }

                        return responseBody;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($" Error: {ex.Message}");
                throw;
            }
        }

        public static async Task<string> EnviarFacturaElectronicaAsync(
                                                                        string urlRecepcionFactura,
                                                                        string xmlFacturaFirmada,
                                                                        string tokenBearer,
                                                                        string nombreArchivoXml = "ecf.xml",
                                                                        CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrWhiteSpace(urlRecepcionFactura))
            {
                throw new ArgumentNullException(nameof(urlRecepcionFactura), "La URL de recepción no puede estar vacía.");
            }

            if (string.IsNullOrWhiteSpace(xmlFacturaFirmada))
            {
                throw new ArgumentException("El contenido del XML de la factura es requerido.", nameof(xmlFacturaFirmada));
            }

            try
            {
                using (HttpClient client = new HttpClient())
                {
                    // Limpiar y formatear el token Bearer
                    string tokenLimpio = tokenBearer?.Trim() ?? string.Empty;
                    if (tokenLimpio.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    {
                        tokenLimpio = tokenLimpio.Substring(7).Trim();
                    }

                    client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", tokenLimpio);
                    client.DefaultRequestHeaders.Add("accept", "application/json");

                    using (var form = new MultipartFormDataContent())
                    {
                        byte[] xmlBytes = Encoding.UTF8.GetBytes(xmlFacturaFirmada);

                        var fileContent = new ByteArrayContent(xmlBytes);
                        fileContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("text/xml");

                        // Asignar el contenido al parámetro 'xml' con el nombre del archivo
                        form.Add(fileContent, "xml", Path.GetFileName(nombreArchivoXml));

                        HttpResponseMessage response = await client.PostAsync(urlRecepcionFactura, form, cancellationToken);
                        string responseBody = await response.Content.ReadAsStringAsync();

                        if (response.IsSuccessStatusCode)
                        {
                            Console.WriteLine(responseBody);
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
            }
            catch (Exception ex)
            {
                Console.WriteLine($" Error: {ex.Message}");
                return $" Error: {ex.Message}";
            }
        }

        public static string EnviarTokenSincrona(string urlSemilla, string passCert, string jsonInvoiceFO)
        {
            return ObtenerSemilla(urlSemilla, passCert, jsonInvoiceFO).GetAwaiter().GetResult();
        }

        public static string ObtenerFacturaAprobacionComercialSincrona(string urlSemilla, string passCert, string jsonFactura)
        {
            return ObtenerSemillaAprobacionComercial(urlSemilla, passCert, jsonFactura).GetAwaiter().GetResult();
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

        public static CertCheckResult FindCertificateFromWINDOWS(string thumbprint)
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
                string jsonString;

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
                        codigoseguridad = _CodigoSeguridad,
                        root = _Root
                    };
          
                    jsonString = JsonConvert.SerializeObject(resultado);

                    return jsonString;
                }
                else
                {
                    Console.WriteLine($"Error al obtener el XML Código: {response.StatusCode}");
                    return $"Error: {response.StatusCode} - {responseBody}";
                }
            }
        }

        public static async Task<string> ObtenerSemillaAprobacionComercial(string urlSemilla, string passCert,string jsonFactura)
        {
            using (HttpClient client = new HttpClient())
            {
                HttpResponseMessage response = await client.GetAsync(urlSemilla);
                string responseBody = await response.Content.ReadAsStringAsync();
                string jsonString;

                if (response.IsSuccessStatusCode)
                {
                    string xmlSemilla = await response.Content.ReadAsStringAsync();

                    _XMLSemilla = xmlSemilla;

                    string JsonEnviado = await FirmarSemillaAprobacionComercial(passCert, jsonFactura);

                    var resultado = new
                    {
                        json = JsonEnviado,
                        encf = _eNCFGlobal,
                        xmlsemilla = _XMLSemilla,
                        xmlsemillafirmada = _XMLSemillaFirmada,
                        token = _tokenGlobal,
                        xmlfactura = _XMLFactura,
                        xmlfacturafirmada = _XMLFacturaFirmada,
                        codigoseguridad = _CodigoSeguridad,
                        root = _Root
                    };

                    jsonString = JsonConvert.SerializeObject(resultado);

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

                _eNCFGlobal = (jsonObj["ECF"]?["Encabezado"]?["IdDoc"]?["eNCF"] ?? jsonObj["RFCE"]?["Encabezado"]?["IdDoc"]?["eNCF"])?.ToString();
                _RNCEmisorGlobal = (jsonObj["ECF"]?["Encabezado"]?["Emisor"]?["RNCEmisor"] ?? jsonObj["RFCE"]?["Encabezado"]?["Emisor"]?["RNCEmisor"])?.ToString();
                _Root = jsonObj["ECF"] != null ? "ECF" : (jsonObj["RFCE"] != null ? "RFCE" : null);

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

        public static async Task<string> FirmarSemillaAprobacionComercial(string passCert, string jsonFactura)
        {
            try
            {

                XmlDocument xmlDoc = new XmlDocument();

                xmlDoc.LoadXml(_XMLSemilla);

                SignXmlSeed(xmlDoc, thumbprint2026, passCert);

                string xmlSemillaFirmada = xmlDoc.OuterXml;
                _XMLSemillaFirmada = xmlSemillaFirmada;

                Console.WriteLine(_XMLSemillaFirmada);

                JObject jsonObj = JObject.Parse(jsonFactura);

                _eNCFGlobal = (jsonObj["ECF"]?["Encabezado"]?["IdDoc"]?["eNCF"] ?? jsonObj["RFCE"]?["Encabezado"]?["IdDoc"]?["eNCF"])?.ToString();
                _RNCEmisorGlobal = (jsonObj["ECF"]?["Encabezado"]?["Emisor"]?["RNCEmisor"] ?? jsonObj["RFCE"]?["Encabezado"]?["Emisor"]?["RNCEmisor"])?.ToString();
                _Root = jsonObj["ECF"] != null ? "ECF" : (jsonObj["RFCE"] != null ? "RFCE" : null);

                XmlDocument xmlDocument = JsonConvert.DeserializeXmlNode(jsonFactura);

                XmlDeclaration xmlDeclaration = xmlDocument.CreateXmlDeclaration("1.0", "utf-8", null);
                XmlElement root = xmlDocument.DocumentElement;
                xmlDocument.InsertBefore(xmlDeclaration, root);

                string xmlFactura = xmlDocument.OuterXml;
                _XMLFactura = xmlFactura;

                string xmlFacturaFirmada = await FirmarFactura(passCert);

                return jsonFactura;

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
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.LoadXml(_XMLFactura);

                SignXmlInvoice(xmlDoc, thumbprint2026, passCert);

                GetSignatureValueFromSignedXml(xmlDoc);

                string xmlFacturaFirmada = xmlDoc.OuterXml;
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

        public static string EnviarFacturaElectronicaAprobacionComercialSincrona(string urlValidarSemilla, string urlRecepcionFacturaAprobacionComercial, string urlConsultaFactura)
        {
            return ValidarSemillaAprobacionComercial(urlValidarSemilla, urlRecepcionFacturaAprobacionComercial, urlConsultaFactura).GetAwaiter().GetResult();
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

        public static async Task<string> ValidarSemillaAprobacionComercial(string urlValidarSemilla, string urlRecepcionFacturaAprobacionComercial, string urlConsultaFactura)
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

                            string JsonFinal = await EnviarFacturaElectronicaAprobacionComercial(urlRecepcionFacturaAprobacionComercial, urlConsultaFactura);
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
                            if (_Root == "RFCE")
                            {
                                Console.WriteLine(responseBody);
                                var json = JObject.Parse(responseBody);
                                return responseBody;
                            }
                            else
                            {
                                Console.WriteLine(responseBody);
                                var json = JObject.Parse(responseBody);
                                _trackIdGlobal = json["trackId"]?.ToString();

                                string estadoFacturaJson = await ConsultarEstadoFacturaElectronica(urlConsultaFactura);
                                return estadoFacturaJson;
                            }
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

        public static async Task<string> EnviarFacturaElectronicaAprobacionComercial(string urlRecepcionFacturaAprobacionComercial, string urlConsultaFactura)
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

                        HttpResponseMessage response = await client.PostAsync(urlRecepcionFacturaAprobacionComercial, form);
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

    }

}
