"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.trainingMaterials = trainingMaterials;
const equipment = ['cup', 'cone', 'ball', 'post'];
// Equipment is reused between frames and successive exercises, so retain maxima.
function trainingMaterials(rows, diagrams) {
    const maxima = { cup: 0, cone: 0, ball: 0, post: 0 };
    let bib = false, missingDiagramCount = 0;
    for (const row of rows) {
        const selected = diagrams.find(d => d.trainingDrillId === row.id)
            ?? diagrams.find(d => !d.trainingDrillId && d.drillId === row.drillId);
        try {
            const data = typeof selected?.data === 'string' ? JSON.parse(selected.data) : selected?.data;
            if (!data || typeof data !== 'object')
                throw new Error('Missing diagram');
            const value = data;
            const frames = Array.isArray(value.frames) && value.frames.length ? value.frames
                : Array.isArray(value.items) ? [{ items: value.items }] : null;
            if (!frames || frames.some((frame) => !frame || !Array.isArray(frame.items)))
                throw new Error('Invalid diagram');
            const colors = new Set();
            for (const frame of frames) {
                const counts = { cup: 0, cone: 0, ball: 0, post: 0 };
                for (const item of frame.items) {
                    if (!item || typeof item !== 'object')
                        continue;
                    if (equipment.includes(item.type))
                        counts[item.type]++;
                    if (item.type === 'player')
                        colors.add(item.color || (item.side === 'away' ? 'red' : 'blue'));
                }
                for (const type of equipment)
                    maxima[type] = Math.max(maxima[type], counts[type]);
            }
            bib || (bib = colors.size >= 2);
        }
        catch {
            missingDiagramCount++;
        }
    }
    const names = { cup: ['Coupelle', 'Coupelles'], cone: ['Cône', 'Cônes'], ball: ['Ballon', 'Ballons'], post: ['Poteau', 'Poteaux'] };
    const items = equipment
        .filter(type => maxima[type] > 0)
        .map(type => ({ type, label: names[type][maxima[type] > 1 ? 1 : 0], quantity: maxima[type] }));
    if (bib)
        items.push({ type: 'bib', label: 'Chasubles', quantity: null });
    return { items, drillCount: rows.length, missingDiagramCount };
}
