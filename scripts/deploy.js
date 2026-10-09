const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  console.log("Deploying FileKeyManager contract...");

  const FileKeyManager = await hre.ethers.getContractFactory("FileKeyManager");
  const contract = await FileKeyManager.deploy();
  await contract.waitForDeployment();

  const contractAddress = await contract.getAddress();
  console.log(`FileKeyManager deployed successfully to: ${contractAddress}`);

  // Export deployment info (ABI and address) for Python web3.py integration
  const artifactPath = path.join(__dirname, "../artifacts/contracts/FileKeyManager.sol/FileKeyManager.json");
  if (fs.existsSync(artifactPath)) {
    const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
    const deploymentInfo = {
      address: contractAddress,
      abi: artifact.abi,
      bytecode: artifact.bytecode
    };

    const outputDir = path.join(__dirname, "../contracts/build");
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    fs.writeFileSync(
      path.join(outputDir, "FileKeyManager.json"),
      JSON.stringify(deploymentInfo, null, 2)
    );
    console.log("Saved deployment artifact to contracts/build/FileKeyManager.json");
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
