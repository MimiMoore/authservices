using Microsoft.Owin;
using Microsoft.Owin.Hosting;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using Owin;
using Kentor.AuthServices.WebSso;
using System.IO;
using System.Xml.Linq;
using System.Security.Cryptography.Xml;

namespace Kentor.AuthServices.Tests.Helpers
{
    [TestClass]
    public class StubServer
    {
        private static IDisposable host;

        static IDictionary<string, string> GetContent()
        {
            var content = new Dictionary<string, string>();

            content["/idpMetadata"] = 
 $@"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata""
    entityID=""http://localhost:13428/idpMetadata"" validUntil=""2100-01-02T14:42:43Z"">
    <IDPSSODescriptor
      protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
      <KeyDescriptor>
        {SignedXmlHelper.KeyInfoXml}
      </KeyDescriptor>
      <SingleSignOnService
        Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST""
        Location=""http://localhost:{IdpMetadataSsoPort}/acs""/>
      <ArtifactResolutionService index=""4660""
        Binding=""urn:oasis:names:tc:SAML:2.0:bindings:SOAP""
        Location=""http://localhost:{IdpMetadataSsoPort}/ars""/>
      <ArtifactResolutionService index=""117""
        Binding=""urn:oasis:names:tc:SAML:2.0:bindings:SOAP""
        Location=""http://localhost:{IdpMetadataSsoPort}/ars2""/>
      <SingleLogoutService
        Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect""
        Location=""http://localhost:{IdpMetadataSsoPort}/logout""
        ResponseLocation=""http://localhost:{IdpMetadataSsoPort}/logoutResponse""/>
    </IDPSSODescriptor>
  </EntityDescriptor>
";

            content["/idpMetadataNoCertificate"] =
@"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata""
    entityID=""http://localhost:13428/idpMetadataNoCertificate"" cacheDuration=""PT15M"">
    <IDPSSODescriptor
      protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
      <SingleSignOnService
        Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect""
        Location=""http://localhost:13428/acs""/>
      <SingleLogoutService
        Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect""
        Location=""http://localhost:13428/logout""/>
    </IDPSSODescriptor>
  </EntityDescriptor>";

            content["/idpMetadataOtherEntityId"] = 
$@"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata""
    entityID=""http://other.entityid.example.com"">
    <IDPSSODescriptor
      protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol""
      WantAuthnRequestsSigned=""true"">
      <KeyDescriptor use=""signing"">
        {SignedXmlHelper.KeyInfoXml}
      </KeyDescriptor>
      <SingleSignOnService
        Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect""
        Location=""http://wrong.entityid.example.com/acs""/>
    </IDPSSODescriptor>
  </EntityDescriptor>";

            content["/federationMetadata"] = 
$@"<EntitiesDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"" validUntil=""2100-01-01T14:43:15Z"">
  <EntityDescriptor entityID=""http://idp.federation.example.com/metadata"">
    <IDPSSODescriptor
      protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
      <KeyDescriptor use=""signing"">
        {SignedXmlHelper.KeyInfoXml}
      </KeyDescriptor>
      <SingleSignOnService
        Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect""
        Location=""http://idp.federation.example.com/ssoService"" />
    </IDPSSODescriptor>
  </EntityDescriptor>
  <EntityDescriptor entityID=""http://sp.federation.example.com/metadata"">
    <SPSSODescriptor
      protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
      <AssertionConsumerService index=""0""
        Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST""
        Location=""http://sp.federation.example.com/acs"" />
    </SPSSODescriptor>
  </EntityDescriptor>
</EntitiesDescriptor>
";

            if (IdpAndFederationShortCacheDurationAvailable)
            {
                content["/federationMetadataVeryShortCacheDuration"] = 
$@"<EntitiesDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"" cacheDuration=""PT0.001S"">
  <EntityDescriptor entityID=""http://idp1.federation.example.com/metadata"">
    <IDPSSODescriptor
      protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
      <KeyDescriptor use=""signing"">
        {SignedXmlHelper.KeyInfoXml}
      </KeyDescriptor>
      <SingleSignOnService
        Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect""
        Location=""http://idp1.federation.example.com:{IdpAndFederationVeryShortCacheDurationPort}/ssoService"" />
    </IDPSSODescriptor>
  </EntityDescriptor>
  <EntityDescriptor entityID=""http://idp2.federation.example.com/metadata"">
    <IDPSSODescriptor
      protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
      <KeyDescriptor use=""signing"">
        {SignedXmlHelper.KeyInfoXml}
      </KeyDescriptor>
      <SingleSignOnService
        Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect""
        Location=""http://idp2.federation.example.com:{IdpAndFederationVeryShortCacheDurationPort}/ssoService"" />
    </IDPSSODescriptor>
  </EntityDescriptor>
  <EntityDescriptor entityID=""http://sp.federation.example.com/metadata"">
    <SPSSODescriptor
      protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
      <AssertionConsumerService index=""0""
        Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST""
        Location=""http://sp.federation.example.com/acs"" />
    </SPSSODescriptor>
  </EntityDescriptor>
</EntitiesDescriptor>";
            }

            if (FederationVeryShortCacheDurationSecondAlternativeEnabled)
            {
                content["/federationMetadataVeryShortCacheDuration"] = 
$@"<EntitiesDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"" cacheDuration=""PT0.001S"">
  <EntityDescriptor entityID=""http://idp1.federation.example.com/metadata"">
    <IDPSSODescriptor
      protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
      <KeyDescriptor use=""signing"">
        {SignedXmlHelper.KeyInfoXml}
      </KeyDescriptor>
      <SingleSignOnService
        Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect""
        Location=""http://idp1.federation.example.com:{IdpAndFederationVeryShortCacheDurationPort}/ssoService"" />
    </IDPSSODescriptor>
  </EntityDescriptor>
  <EntityDescriptor entityID=""http://idp3.federation.example.com/metadata"">
    <IDPSSODescriptor
      protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
      <KeyDescriptor use=""signing"">
        {SignedXmlHelper.KeyInfoXml}
      </KeyDescriptor>
      <SingleSignOnService
        Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect""
        Location=""http://idp3.federation.example.com:{IdpAndFederationVeryShortCacheDurationPort}/ssoService"" />
    </IDPSSODescriptor>
  </EntityDescriptor>
  <EntityDescriptor entityID=""http://sp.federation.example.com/metadata"">
    <SPSSODescriptor
      protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
      <AssertionConsumerService index=""0""
        Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST""
        Location=""http://sp.federation.example.com/acs"" />
    </SPSSODescriptor>
  </EntityDescriptor>
</EntitiesDescriptor>";
            }

            if (IdpAndFederationShortCacheDurationAvailable)
            {
                content["/federationMetadataShortCacheDuration"] = 
$@"<EntitiesDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata"" cacheDuration=""PT0.200S"">
  <EntityDescriptor entityID=""http://idp1.federation.example.com/metadata"">
    <IDPSSODescriptor
      protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
      <KeyDescriptor use=""signing"">
        {SignedXmlHelper.KeyInfoXml}
      </KeyDescriptor>
      <SingleSignOnService
        Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect""
        Location=""http://idp1.federation.example.com/ssoService"" />
    </IDPSSODescriptor>
  </EntityDescriptor>
  <EntityDescriptor entityID=""http://idp2.federation.example.com/metadata"">
    <IDPSSODescriptor
      protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
      <KeyDescriptor use=""signing"">
        {SignedXmlHelper.KeyInfoXml}
      </KeyDescriptor>
      <SingleSignOnService
        Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect""
        Location=""http://idp2.federation.example.com/ssoService"" />
    </IDPSSODescriptor>
  </EntityDescriptor>
  <EntityDescriptor entityID=""http://sp.federation.example.com/metadata"">
    <SPSSODescriptor
      protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
      <AssertionConsumerService index=""0""
        Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST""
        Location=""http://sp.federation.example.com/acs"" />
    </SPSSODescriptor>
  </EntityDescriptor>
</EntitiesDescriptor>";
            }

            content["/idpMetadataWithMultipleBindings"] = 
$@"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata""
  entityID=""http://localhost:13428/idpMetadataWithMultipleBindings"">
  <IDPSSODescriptor
    protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
    <KeyDescriptor use=""signing"">
      {SignedXmlHelper.KeyInfoXml}
    </KeyDescriptor>
    <SingleSignOnService
      Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST""
      Location=""http://idp2Bindings.example.com/POST"" />
    <SingleSignOnService
      Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect""
      Location=""http://idp2Bindings.example.com/Redirect"" />
  </IDPSSODescriptor>
</EntityDescriptor>";

            content["/idpMetadataDifferentEntityId"] = 
$@"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata""
  entityID=""some-idp"">
  <IDPSSODescriptor
    protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
    <KeyDescriptor use=""signing"">
      {SignedXmlHelper.KeyInfoXml}
    </KeyDescriptor>
    <SingleSignOnService
      Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect""
      Location=""http://idp.example.com/SsoService"" />
  </IDPSSODescriptor>
</EntityDescriptor>";

            content["/idpMetadataWithArtifactBinding"] = 
$@"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata""
  entityID=""http://localhost:13428/idpMetadataWithArtifactBinding"">
  <IDPSSODescriptor
    protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
    <KeyDescriptor use=""signing"">
      {SignedXmlHelper.KeyInfoXml}
    </KeyDescriptor>
    <SingleSignOnService
      Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact""
      Location=""http://idpArtifact.example.com/Artifact"" />
    <SingleSignOnService
      Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST""
      Location=""http://idpArtifact.example.com/POST"" />
  </IDPSSODescriptor>
</EntityDescriptor>";

            if (IdpAndFederationShortCacheDurationAvailable)
            {
                string keyDescriptor = IdpVeryShortCacheDurationIncludeInvalidKey ? "Gibberish" : SignedXmlHelper.KeyInfoXml2;
                string keyDescriptorXml = $@"<KeyDescriptor use=""signing"">{keyDescriptor}</KeyDescriptor>";
                string keyElement = IdpVeryShortCacheDurationIncludeKey ? keyDescriptorXml : "";

                content["/idpMetadataVeryShortCacheDuration"] = 
$@"<EntityDescriptor xmlns=""urn:oasis:names:tc:SAML:2.0:metadata""
entityID=""http://localhost:13428/idpMetadataVeryShortCacheDuration"" cacheDuration=""PT0.001S"">
<IDPSSODescriptor
    protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
    {keyElement}
    <SingleSignOnService
      Binding=""{IdpVeryShortCacheDurationBinding}""
      Location=""http://localhost:{IdpAndFederationVeryShortCacheDurationPort}/acs""/>
    <ArtifactResolutionService
      index=""0""
      Location=""http://localhost:{IdpAndFederationVeryShortCacheDurationPort}/ars""
      Binding=""urn:oasis:names:tc:SAML:2.0:bindings:SOAP"" />
      <SingleLogoutService
        Binding=""{IdpVeryShortCacheDurationBinding}""
        Location=""http://localhost:{IdpAndFederationVeryShortCacheDurationPort}/logout""
        ResponseLocation=""http://localhost:{IdpAndFederationVeryShortCacheDurationPort}/logoutResponse""/>
</IDPSSODescriptor>
</EntityDescriptor>";
            }

            return content;
        }

        public static int IdpMetadataSsoPort { get; set; } = 13428;
        public static int IdpAndFederationVeryShortCacheDurationPort { get; set; } = 80;
        public static Uri IdpVeryShortCacheDurationBinding { get; set; } = Saml2Binding.HttpRedirectUri;
        public static bool IdpVeryShortCacheDurationIncludeInvalidKey { get; set; }
        public static bool IdpVeryShortCacheDurationIncludeKey { get; set; } = true;
        public static bool IdpAndFederationShortCacheDurationAvailable { get; set; } = true;
        public static bool FederationVeryShortCacheDurationSecondAlternativeEnabled { get; set; } = false;

        [AssemblyInitialize]
        public static void Start(TestContext testContext)
        {
            host = WebApp.Start("http://localhost:13428", app =>
            {
                app.Use(async (ctx, next) =>
                {
                    string data;

                    switch (ctx.Request.Path.ToString())
                    {
                        case "/ars":
                            ArtifactResolutionService(ctx);
                            return;
                        default:
                            var content = GetContent();
                            if (content.TryGetValue(ctx.Request.Path.ToString(), out data))
                            {
                                await ctx.Response.WriteAsync(data);
                                return;
                            }
                            break;
                    }
                    await next.Invoke();
                });
            });
        }

        private static void ArtifactResolutionService(IOwinContext ctx)
        {
            LastArtifactResolutionSoapActionHeader = ctx.Request.Headers["SOAPAction"];

            using (var reader = new StreamReader(ctx.Request.Body))
            {
                var body = reader.ReadToEnd();

                var parsedRequest = XElement.Parse(body);

                var requestId = parsedRequest
                    .Element(Saml2Namespaces.SoapEnvelope + "Body")
                    .Element(Saml2Namespaces.Saml2P + "ArtifactResolve")
                    .Attribute("ID").Value;

                LastArtifactResolutionWasSigned = parsedRequest
                    .Element(Saml2Namespaces.SoapEnvelope + "Body")
                    .Element(Saml2Namespaces.Saml2P + "ArtifactResolve")
                    .Element(XNamespace.Get(SignedXml.XmlDsigNamespaceUrl)+ "Signature")
                    != null;

                var response = 
    $@"<SOAP-ENV:Envelope
    xmlns:SOAP-ENV=""http://schemas.xmlsoap.org/soap/envelope/"">
    <SOAP-ENV:Body>
        <samlp:ArtifactResponse
            xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol""
            xmlns=""urn:oasis:names:tc:SAML:2.0:assertion""
            ID=""_FQvGknDfws2Z"" Version=""2.0""
            InResponseTo = ""{requestId}""
            IssueInstant = ""{DateTime.UtcNow.ToSaml2DateTimeString()}"">
            <Issuer>https://idp.example.com</Issuer>
            <samlp:Status>
                <samlp:StatusCode Value = ""urn:oasis:names:tc:SAML:2.0:status:Success"" />
            </samlp:Status>
            <message>   <child-node /> </message>
        </samlp:ArtifactResponse>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>";

                ctx.Response.Write(response);
            }
        }

        public static string LastArtifactResolutionSoapActionHeader { get; set; }

        public static bool LastArtifactResolutionWasSigned { get; set; }

        [AssemblyCleanup]
        public static void Stop()
        {
            host.Dispose();
        }
    }
}
