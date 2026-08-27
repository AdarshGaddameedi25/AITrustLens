import * as scanService from '../services/scanService.js';
import { successResponse, errorResponse } from '../utils/responseFormatter.js';
import { paginatedResponse } from '../utils/responseFormatter.js';

export async function getScans(req, res, next) {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 20, 50);
    const scanType = req.query.type || null;

    const { scans, total } = await scanService.getUserScans(req.user.id, page, limit, scanType);
    res.json(paginatedResponse(scans, total, page, limit));
  } catch (error) {
    next(error);
  }
}

export async function getScan(req, res, next) {
  try {
    const scan = await scanService.getScanById(req.params.id, req.user.id);
    res.json(successResponse({ scan }));
  } catch (error) {
    if (error.statusCode === 404) {
      return res.status(404).json(errorResponse('NOT_FOUND', error.message));
    }
    next(error);
  }
}

export async function getDashboard(req, res, next) {
  try {
    const stats = await scanService.getDashboardStats(req.user.id);
    res.json(successResponse(stats));
  } catch (error) {
    next(error);
  }
}

export async function deleteScan(req, res, next) {
  try {
    await scanService.deleteScan(req.params.id, req.user.id);
    res.json(successResponse({ deleted: true }));
  } catch (error) {
    if (error.statusCode === 404) {
      return res.status(404).json(errorResponse('NOT_FOUND', error.message));
    }
    next(error);
  }
}
