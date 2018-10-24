package hu.petoendre.nfkm;

import java.io.IOException;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import com.ncipher.km.marshall.NFKM_Key_flags;
import com.ncipher.km.marshall.NFKM_SoftCardIdent;
import com.ncipher.km.nfkm.AppKeyGenerator;
import com.ncipher.km.nfkm.CreateSoftCard;
import com.ncipher.km.nfkm.InvalidPropValue;
import com.ncipher.km.nfkm.Key;
import com.ncipher.km.nfkm.MenuOption;
import com.ncipher.km.nfkm.PropValueMenu;
import com.ncipher.km.nfkm.PropValueString;
import com.ncipher.km.nfkm.SecurityWorld;
import com.ncipher.km.nfkm.SoftCard;
import com.ncipher.nfast.NFException;
import com.ncipher.nfast.connect.ClientException;
import com.ncipher.nfast.connect.CommandTooBig;
import com.ncipher.nfast.connect.ConnectionClosed;
import com.ncipher.nfast.connect.StatusNotOK;
import com.ncipher.nfast.connect.utils.EasyConnection;
import com.ncipher.nfast.marshall.M_ByteBlock;
import com.ncipher.nfast.marshall.M_CipherText;
import com.ncipher.nfast.marshall.M_Cmd;
import com.ncipher.nfast.marshall.M_Cmd_Args_Sign;
import com.ncipher.nfast.marshall.M_Cmd_Reply_Sign;
import com.ncipher.nfast.marshall.M_Command;
import com.ncipher.nfast.marshall.M_KeyID;
import com.ncipher.nfast.marshall.M_Mech;
import com.ncipher.nfast.marshall.M_PlainText;
import com.ncipher.nfast.marshall.M_PlainTextType;
import com.ncipher.nfast.marshall.M_PlainTextType_Data_Bytes;
import com.ncipher.nfast.marshall.M_Reply;
import com.ncipher.nfast.marshall.MarshallContext;
import com.ncipher.nfast.marshall.MarshallTypeError;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;
import iaik.pkcs.pkcs11.Session.UserType;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11RuntimeException;

public class App {

  protected static final long RSA_KEY_SIZE = 2048;

  public static void main(String[] args) {
    try {

      SecurityWorld world = getWorld();

      com.ncipher.km.nfkm.Module module = getUsableModule(world);

      createSoftcard(args, module);

      SoftCard[] softCards = world.getSoftCards();

      findSoftcard(softCards);

      generateKeyToAnExistingSoftcard(world);

      generateKeyViaPkcs11Wrapper();

    } catch (Exception e) {
      e.printStackTrace();
    }
  }
  
  public String sign(String gsuId, byte[] toBeSigned) {
    String signature = null;
    try {

      M_ByteBlock block = new M_ByteBlock(toBeSigned);
      M_PlainText plaintext = new M_PlainText(M_PlainTextType.Bytes, new M_PlainTextType_Data_Bytes(block));

      byte[] signatureBytes = signing(gsuId, plaintext);

      signature = Base64.getEncoder().encodeToString(signatureBytes);

    } catch (Exception e) {
      throw new RuntimeException(e);
    }

    return signature;
  }

  private byte[] signing(String gsuId, M_PlainText plaintext)
    throws NFException {
    SecurityWorld world = getWorld();
    Key keys[] = findSoftcard(world.getSoftCards());
    M_Command cmd = new M_Command(M_Cmd.Sign, 0,
      new M_Cmd_Args_Sign(0, keys[0].load(getUsableModule(world)), M_Mech.RSAhSHA256pPKCS1, plaintext));

    M_Reply reply = null;

    EasyConnection easyConnection = new EasyConnection(world.getConnection());
    reply = easyConnection.transactChecked(cmd);

    M_CipherText signatureText;
    signatureText = ((M_Cmd_Reply_Sign) reply.reply).sig;

    MarshallContext mc = new MarshallContext();
    signatureText.marshall(mc);

    byte signatureWithPlusBytes[] = mc.getBytes();
    byte signatureBytes[] = new byte[mc.getBytes().length - 8];
    for (int i = 8, y = 0; i < mc.getBytes().length; i++, y++) {
      signatureBytes[y] = signatureWithPlusBytes[i];
    }
    return signatureBytes;
  }

  public static Key generate_key(WorldCallbacks wcb, SecurityWorld world, String type, int len, int protection,
    String appname, String ident)
    throws NFException {
    AppKeyGenerator akg = world.getAppKeyGenerator(appname);
    try {
      // setStringProperty(akg, "ident", ident);
      setMenuProperty(akg, "type", type);
      setStringProperty(akg, "size", Integer.toString(len));
      setStringProperty(akg, "plainname", ident);
      setMenuProperty(akg, "protect", "softcard");
      InvalidPropValue badprops[] = akg.check();
      if (badprops.length > 0)
        throw new BadKeyGenProperties(badprops);
      com.ncipher.km.nfkm.Module module = getUsableModule(world);
      return akg.generate(module, null/* cardset */);
    } finally {
      akg.cancel();
    }
  }

  public static SecurityWorld getWorld() throws NFException {
    WorldCallbacks wcb = new WorldCallbacks();
    try {
      return new SecurityWorld(null, wcb, null, true);
    } catch (NFException e) {
      throw new NFException();
    }
  }

  public static com.ncipher.km.nfkm.Module getUsableModule(SecurityWorld world)
    throws NFException {
    com.ncipher.km.nfkm.Module modules[] = world.getModules();
    for (int m = 0; m < modules.length; ++m)
      if (modules[m].isUsable())
        return modules[m];
    throw new NFException();
  }

  private static Key[] findSoftcard(SoftCard[] softCards) throws NFException {
    Key keys[] = null;
    
    for (SoftCard softCard : softCards) {
      if (softCard.getName().contains("korte") || softCard.getName().contains("alma")) {
        keys = softCard.listKeys();
        if (keys.length > 0) {
          for (Key key : keys) {
//            key.erase();
            return keys;
          }
        }
//        softCard.erase();
      }
    }
    
    return keys;
  }

  private static void createSoftcard(String[] args, com.ncipher.km.nfkm.Module module) throws NFException {
    for (Long i = Long.valueOf(args[0]); i < Long.valueOf(args[1]); i++) {
      CreateSoftCard softcard = new CreateSoftCard(new CallbackExtend("password"), module, false, "fuge" + i);
      softcard.go();
    }
  }

  private static void setStringProperty(AppKeyGenerator akg, String propname, String propvalue)
    throws NFException {
    PropValueString pvs = (PropValueString) akg.getProperty(propname).getValue();
    pvs.value = propvalue;
  }

  private static void setMenuProperty(AppKeyGenerator akg, String propname, String propvalue)
    throws NFException {
    PropValueMenu pvm = (PropValueMenu) akg.getProperty(propname).getValue();
    MenuOption options[] = pvm.getOptions();
    for (int i = 0; i < options.length; ++i)
      if (options[i].getName().equals(propvalue)) {
        pvm.value = i;
        return;
      }
    throw new InvalidMenuItem(propvalue);
  }
  
  private static void generateKeyViaPkcs11Wrapper() throws IOException, TokenException {
    Module iaikModule = Module
      .getInstance("cknfast-64.dll");
    iaikModule.initialize(null);

    Slot[] slotList = iaikModule.getSlotList(Module.SlotRequirement.ALL_SLOTS);

    System.out.println("slotList.length " + slotList.length);

    for (Slot slot : slotList) {
      TokenInfo tokenInfo = slot.getToken().getTokenInfo();
      if (tokenInfo.getLabel().trim().contains("korte") || tokenInfo.getLabel().trim().contains("alma")) {
        Token token = slot.getToken();
        Session session = token.openSession(Token.SessionType.SERIAL_SESSION,
          Token.SessionReadWriteBehavior.RW_SESSION,
          null, null);
        session.login(UserType.USER, "Almafa123456".toCharArray());

        Mechanism keyGenMechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);
        RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();
        RSAPublicKey publicKeyTemplate = new RSAPublicKey();

        privateKeyTemplate.getToken().setBooleanValue(true); // this should bind the key pair to the token
        privateKeyTemplate.getSensitive().setBooleanValue(true);
        privateKeyTemplate.getPrivate().setBooleanValue(true);
        privateKeyTemplate.getDecrypt().setBooleanValue(false);
        privateKeyTemplate.getSign().setBooleanValue(true);
        privateKeyTemplate.getSignRecover().setBooleanValue(false);
        privateKeyTemplate.getUnwrap().setBooleanValue(false);
        privateKeyTemplate.getExtractable().setBooleanValue(false);
        privateKeyTemplate.getLabel().setCharArrayValue(tokenInfo.getLabel().trim().toCharArray());

        publicKeyTemplate.getToken().setBooleanValue(true); // this should bind the key pair to the token
        publicKeyTemplate.getEncrypt().setBooleanValue(false);
        publicKeyTemplate.getVerify().setBooleanValue(true);
        publicKeyTemplate.getVerifyRecover().setBooleanValue(false);
        publicKeyTemplate.getWrap().setBooleanValue(false);
        publicKeyTemplate.getModulusBits().setLongValue(RSA_KEY_SIZE);
        publicKeyTemplate.getPublicExponent().setByteArrayValue(new byte[] { 0x01, 0x00, 0x01 });
        publicKeyTemplate.getLabel().setCharArrayValue(tokenInfo.getLabel().trim().toCharArray());

        iaik.pkcs.pkcs11.objects.KeyPair keyPair = null;
        try {
          keyPair = session.generateKeyPair(keyGenMechanism, publicKeyTemplate, privateKeyTemplate);
        } catch (PKCS11RuntimeException e) {
          throw new RuntimeException(e);
        }

        System.out.println("keyPair " + keyPair);
      }
    }
  }

  private static void generateKeyToAnExistingSoftcard(SecurityWorld world) throws NFException {
    String appname, ident, type = "RSA";
    appname = "pkcs11";
    ident = "CS1234567891234456";
    int size = 2048;

    byte[] hashTestForKEy = Base64.getDecoder().decode("7q1rojFQ6hFHyccUblZATN0p2e0=");
    NFKM_SoftCardIdent hashTestForKEySoftCardIdent2 = new NFKM_SoftCardIdent();
    hashTestForKEySoftCardIdent2.value = hashTestForKEy;

    SoftCard[] softCardTestForKEy = world.getSoftCards();
    WorldCallbacks wcb = new WorldCallbacks();
    wcb.configured_softcard = softCardTestForKEy[0];
    System.out.println(new Date());
    Key key = generate_key(wcb, world, type, size, NFKM_Key_flags.f_ProtectionPassPhrase, appname, ident);
    System.out.println(key);
  }

}
