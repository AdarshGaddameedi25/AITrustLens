import prisma from './src/config/database.js';

async function checkLastScan() {
  const lastResult = await prisma.scanResult.findFirst({
    orderBy: { createdAt: 'desc' }
  });
  console.log("Last scan result AI Explanation:", JSON.stringify(lastResult?.aiExplanation, null, 2));
  console.log("Rule set version:", lastResult?.ruleSetVersion);
  await prisma.$disconnect();
}

checkLastScan();
