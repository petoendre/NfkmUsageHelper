package hu.petoendre.nfkm;

import com.ncipher.nfast.NFException;

public class InvalidMenuItem extends NFException {

    public InvalidMenuItem(String value) {
      super("no such option as '" + value + "'");
    }

}
