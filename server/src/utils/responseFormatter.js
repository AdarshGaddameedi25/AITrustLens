/**
 * Standard API response formatters.
 * All backend responses must use these helpers for consistency.
 */

export function successResponse(data, meta = {}) {
  return {
    success: true,
    data,
    ...meta,
  };
}

export function errorResponse(code, message, details = null) {
  const response = {
    success: false,
    error: {
      code,
      message,
    },
  };
  // Only include details in development
  if (details && process.env.NODE_ENV === 'development') {
    response.error.details = details;
  }
  return response;
}

export function paginatedResponse(data, total, page, limit) {
  return {
    success: true,
    data,
    pagination: {
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
    },
  };
}
