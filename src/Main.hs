
-- General
import qualified Data.ByteString as BS
import Data.Monoid ((<>))
import Control.Applicative ((<|>))
-- PEM loading
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509CS
import qualified Data.PEM as PEM
-- Client
import qualified Network.Wreq as Wreq
import Control.Lens ((&), (.~))
import qualified Network.HTTP.Client.TLS as TLSClient
import qualified Network.Connection as Connection
import Network.TLS as TLS
import Network.Socket (HostName)
import Data.Default (def)
-- Server
import qualified Network.Wai.Handler.Warp
import qualified Network.Wai.Handler.WarpTLS
import qualified Network.Wai
-- Command line
import qualified Options.Applicative as Opt


decodeCertPem :: BS.ByteString -> Either String X509.SignedCertificate
decodeCertPem bs = do
    pems <- PEM.pemParseBS bs
    pem <- case pems of
        [] -> Left "Empty PEM data"
        [x] -> return x
        _ -> Left "Too many PEM sections"
    X509.decodeSignedObject (PEM.pemContent pem)

loadCertPem :: FilePath -> IO (Either String X509.SignedCertificate)
loadCertPem path = decodeCertPem <$> BS.readFile path

main :: IO ()
main = do
    opts <- Opt.execParser (Opt.info (Opt.helper <*> action) Opt.fullDesc)
    case opts of
        Client certPath serverHost -> client certPath serverHost
        Server certPath keyPath -> server certPath keyPath

client :: FilePath -> TLS.HostName -> IO ()
client certPath server = do
    cert <- either error id <$> loadCertPem certPath
    res <- Wreq.getWith (managerWithCert server cert) ("http://" ++ server ++ "/")
    print res


managerWithCert :: TLS.HostName -> X509.SignedCertificate -> Wreq.Options
managerWithCert hostname cert = Wreq.defaults & Wreq.manager .~ Left mgrSettings
    where 
    mgrSettings = TLSClient.mkManagerSettings tlsSettings Nothing
    tlsSettings = Connection.TLSSettings clientParams
    clientParams = TLS.ClientParams {
        clientUseMaxFragmentLength = Nothing,
        clientServerIdentification = (hostname, ""),
        clientUseServerNameIndication = False,
        clientWantSessionResume = Nothing,
        clientShared = def {sharedCAStore = X509CS.makeCertificateStore [cert]},
        -- NB: I think I need to modify clientHooks onServerCertificate to rule out anything besides [cert]
        clientHooks = def, 
        clientSupported = def,
        clientDebug = def
    }

server :: FilePath -> FilePath -> IO ()
server certPath keyPath = do
    cert <- either error id <$> loadCertPem certPath


data Action
    = Client {serverCertPath :: FilePath, serverHost :: TLS.HostName}
    | Server {serverCertPath :: FilePath, serverKeyPath :: FilePath}

action :: Opt.Parser Action
action = client <|> server
    where
    server = Opt.flag' () serverSwitch *> (Server <$> Opt.strOption serverCertPath <*> Opt.strOption serverKeyPath)
    serverSwitch = Opt.long "server"
                <> Opt.help "Run as server"
    client = Opt.flag' () clientSwitch *> (Client <$> Opt.strOption serverCertPath <*> Opt.strOption serverHost)
    clientSwitch = Opt.long "client"
                <> Opt.help "Run as client"
    serverCertPath = Opt.long "cert-path" 
                  <> Opt.metavar "FILE.pem" 
                  <> Opt.help "The PEM file containing the server's TLS cert"
                  <> Opt.value "certificate.pem"
                  <> Opt.showDefault
    serverKeyPath = Opt.long "key-path" 
                  <> Opt.metavar "FILE.pem" 
                  <> Opt.help "The PEM file containing the server's TLS key"
                  <> Opt.value "key.pem"
                  <> Opt.showDefault        
    serverHost = Opt.long "server-host"
              <> Opt.metavar "HOST"
              <> Opt.help "The server's hostname"
