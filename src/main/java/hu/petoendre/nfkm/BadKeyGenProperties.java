package hu.petoendre.nfkm;

import com.ncipher.km.nfkm.InvalidPropValue;
import com.ncipher.nfast.NFException;

public class BadKeyGenProperties extends NFException{

  public InvalidPropValue badprops[];

  public BadKeyGenProperties(InvalidPropValue badprops_[]) {
    super("invalid key generation properties");
    badprops = badprops_;
  }
}
