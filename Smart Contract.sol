
pragma solidity >=0.4.24;
import "./VerifyRingSignaturePrecompiled.sol";
pragma experimental ABIEncoderV2;

contract SmartContract{
    mapping (uint =>string) uidList;//授权计算证明uid列表
    uint numUID=0;//uid个数
    mapping(uint =>string) proofList;//授权证明proof
    uint numProofs=0;//proof数量
    mapping(uint =>string) tagList;//可链接标志列表
    uint numTag=0;//tag数量
    mapping(uint =>string) pkList;//医生列表
    uint numPk=0;//pk数量
    //一个did document
    struct DID{
        string id;
        string controller;
        string []verificationMethod;
        string []assertionMethod;
    }
    DID [] didList;//did document列表
    uint numofdid = 0;
    //获取环成员集合
    function getPublicKeySet(uint256 num) public view returns(string[] memory){
        //初始化返回数组大小
        string[] memory publicKeyList = new string[](uint256(num)*2);
        uint256 random = uint256(keccak256(abi.encodePacked(block.difficulty, block.timestamp)));
        //取模 随机数范围合理
        uint256 t = random%(numPk-1);
        uint flag = 0;
        for(uint i1 = t;i1<numPk-1;i1++){
            publicKeyList[i1] = pkList[i1];
            flag++;
        }
        return publicKeyList;
    }

    VerifyRingSignaturePrecompiled ringsig;
    constructor(){
         ringsig = VerifyRingSignaturePrecompiled(0x5002);
    }

    string result = "fail";
    function verify(string [] memory data)public{
        string memory sigInfo = data[20];
        string memory tagValue = data[8];
        if(selectTag(tagValue) == false){//判断可链接性
            result = "fail to link";//不通过
        }
        else{
            if(ringsig.verify(sigInfo) == false){//环签名验证
                result = "ringsig fail";
            }
            else{
                result = "Success to verify";
                tagList[numTag++] = tagValue;
                result = "Success";    
            }
        }
    }
    function getVerifyResult() public view returns(string memory){
        return result;
    }
    function selectTag(string memory tag) private view returns(bool){
        //初始化返回值
        bool resul = true;
         for(uint i =0;i<numTag;i++){
            if(keccak256(abi.encode(tagList[i]))==keccak256(abi.encode(tag))){
                resul = false;
                break;
            }
        }
        return resul;
    }
    //this one 1
    function proofToChain(string memory data) public{
        proofList[numProofs++] = data;
    }
    function uidToChain(string memory data) public{
        uidList[numUID++] = data;
    }
    function didToChain(string [] memory data, uint size1, uint size2) public{
        DID memory did;
        did.id = data[0];
        did.controller = data[1];
        uint sizeofmethod = size1;
        uint sizeofass = size2;
        string[] memory s = new string[](sizeofmethod);
        for(uint i = 0;i<sizeofmethod;i++){
            s[i] = data[2+i];
        }
        string[] memory s1 = new string[](sizeofass);
        for(uint i = 0;i<sizeofass;i++){
            s1[i] = data[2+sizeofass+i];
        }       
        did.verificationMethod = s;
        did.assertionMethod = s1;
        didList.push(did);
        numofdid++;
    }
   
     //获取proof证明信息
    function getProofInformation(uint num) public view returns(string memory){
        string memory data = "0";
        if(num>=numProofs){
            return data;
        }
        else{
            data = proofList[num];
            return data;
        }
    }
    //获取uid信息
    function getUidInformation(uint num) public view returns(string memory){
        string memory data = "0";
        if(num>=numUID){
            return data;
        }
        else{
            data = uidList[num];
            return data;
        }
    }
    //获取did个数
    function getNumOfDid() public view returns(uint){
        return numofdid;
    }
    //获取proof个数
    function getNumOfproof() public view returns(uint){
        return numProofs;
    }
    //获取uid个数
    function getNumOfuid() public view returns(uint){
        return numUID;
    }

}
