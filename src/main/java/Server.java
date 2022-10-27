import net.link.oath.*;
import org.eclipse.jetty.http.HttpStatus;

import static spark.Spark.*;

public class Server {
    static byte[] secret = {
            0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38,
            0x39, 0x30, 0x31, 0x32,
            0x33, 0x34, 0x35, 0x36,
            0x37, 0x38, 0x39, 0x30};

    public static void main(String[] args) throws InvalidOcraSuiteException, InvalidDataModeException, InvalidHashException, InvalidCryptoFunctionException {
        OCRASuite ocraSuite = new OCRASuite("OCRA-1:HOTP-SHA256-8:QA08");
        String key32 = "12345678901234567890123456789012";
        OCRA ocra = new OCRA(ocraSuite, key32.getBytes(),0,0,0);
        String question = "Hello there";

        get("/validate", (req, res)->{
            String otp = req.queryParams("otp");
            int counter = Integer.parseInt(req.queryParams("counter"));
            HOTP hotp = new HOTP(secret,6,false,-1,0);
            res.type("text/plain");
            if(Integer.parseInt(otp)<100000 || Integer.parseInt(otp)>1000000){
                res.status(HttpStatus.UNAUTHORIZED_401);
                return res;
            }
            if(hotp.validate(counter,otp) == counter +1) {
                res.status(HttpStatus.OK_200);
                return hotp.validate(counter,otp);
            }

            res.status(HttpStatus.UNAUTHORIZED_401);
            return res;
        });

        get("/challange", (req,res)->{
            res.type("plain/text");
            return ocra.generate(0,question,"","",0);
        });
        get("/validation", (req,res)->{
            res.type("plain/text");
            String signature = req.queryParams("signature");
            String challange = ocra.generate(0,question,"","",0);

            try {
                OCRAState ocraState =  ocra.validate(0,challange,"","",0,signature);
                res.status(200);
                return question;
            } catch (InvalidResponseException e) {
                e.printStackTrace();
                res.status(401);
                return res;
            }        });
    }
}