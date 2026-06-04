require "./spec_helper"

describe PDF::Signature::ASN1 do
  describe ".parse / Node#to_der" do
    it "fait un aller-retour octet-pour-octet sur un DER canonique" do
      # SEQUENCE { INTEGER 1, OCTET STRING "ab" }
      der = ::Bytes[0x30, 0x07, 0x02, 0x01, 0x01, 0x04, 0x02, 0x61, 0x62]
      node = PDF::Signature::ASN1.parse(der)
      node.constructed?.should be_true
      node.tag.should eq(0x30_u8)
      node.children.size.should eq(2)
      node.children[0].tag.should eq(0x02_u8)
      node.children[1].content.should eq(::Bytes[0x61, 0x62])
      node.to_der.should eq(der)
    end

    it "encode la forme longue de longueur en DER minimal" do
      content = ::Bytes.new(200, 0x41_u8)
      node = PDF::Signature::ASN1::Node.new(0x04_u8, content: content)
      der = node.to_der
      # 0x04, 0x81 (long form, 1 octet), 0xC8 (=200), puis 200 octets.
      der[0].should eq(0x04_u8)
      der[1].should eq(0x81_u8)
      der[2].should eq(0xC8_u8)
      der.size.should eq(203)
      PDF::Signature::ASN1.parse(der).content.should eq(content)
    end

    it "rejette la forme à numéro de tag élevé (> 30)" do
      expect_raises(PDF::Signature::SignatureError, /multi-octets/) do
        PDF::Signature::ASN1.parse(::Bytes[0x1F, 0x81, 0x00])
      end
    end

    it "rejette la longueur indéfinie (interdite en DER)" do
      expect_raises(PDF::Signature::SignatureError, /indéfinie/) do
        PDF::Signature::ASN1.parse(::Bytes[0x30, 0x80, 0x00, 0x00])
      end
    end
  end

  describe ".encode_oid" do
    it "encode id-aa-timeStampToken (1.2.840.113549.1.9.16.2.14)" do
      PDF::Signature::ASN1.encode_oid("1.2.840.113549.1.9.16.2.14").should eq(
        ::Bytes[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E]
      )
    end

    it "produit un noeud OBJECT IDENTIFIER complet via .oid" do
      PDF::Signature::ASN1.oid("1.2.840.113549.1.9.16.2.14").to_der.should eq(
        ::Bytes[0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0E]
      )
    end
  end

  describe ".sequence / .set / .context_constructed" do
    it "assemble les conteneurs avec les bons tags" do
      PDF::Signature::ASN1.sequence([] of PDF::Signature::ASN1::Node).tag.should eq(0x30_u8)
      PDF::Signature::ASN1.set([] of PDF::Signature::ASN1::Node).tag.should eq(0x31_u8)
      # [1] IMPLICIT (unsignedAttrs) → 0xA1
      PDF::Signature::ASN1.context_constructed(1, [] of PDF::Signature::ASN1::Node).tag.should eq(0xA1_u8)
    end
  end
end
