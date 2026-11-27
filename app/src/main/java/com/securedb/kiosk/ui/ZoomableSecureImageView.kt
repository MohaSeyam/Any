package com.securedb.kiosk.ui

import android.content.Context
import android.graphics.Bitmap
import android.graphics.Matrix
import android.util.AttributeSet
import android.view.GestureDetector
import android.view.MotionEvent
import android.view.ScaleGestureDetector
import androidx.appcompat.widget.AppCompatImageView
import kotlin.math.max
import kotlin.math.min

class ZoomableSecureImageView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : AppCompatImageView(context, attrs, defStyleAttr) {

    private val drawMatrix = Matrix()
    private var currentScale = 1f
    private var baseScale = 1f
    private var lastTouchX = 0f
    private var lastTouchY = 0f
    private var isDragging = false

    private val scaleDetector = ScaleGestureDetector(
        context,
        object : ScaleGestureDetector.SimpleOnScaleGestureListener() {
            override fun onScale(detector: ScaleGestureDetector): Boolean {
                if (currentScale <= 0f) return false
                val factor = detector.scaleFactor
                val targetScale = (currentScale * factor).coerceIn(baseScale, baseScale * 6f)
                val realFactor = targetScale / currentScale
                currentScale = targetScale
                drawMatrix.postScale(realFactor, realFactor, detector.focusX, detector.focusY)
                imageMatrix = drawMatrix
                return true
            }
        }
    )

    private val doubleTapDetector = GestureDetector(
        context,
        object : GestureDetector.SimpleOnGestureListener() {
            override fun onDoubleTap(e: MotionEvent): Boolean {
                fitBitmapToCenter()
                return true
            }
        }
    )

    init {
        scaleType = ScaleType.MATRIX
    }

    fun setSecureBitmap(bitmap: Bitmap) {
        setImageBitmap(bitmap)
        if (width > 0 && height > 0) {
            fitBitmapToCenter()
        } else {
            post { fitBitmapToCenter() }
        }
    }

    private fun fitBitmapToCenter() {
        val d = drawable ?: return
        val vw = width.toFloat()
        val vh = height.toFloat()
        val dw = d.intrinsicWidth.toFloat()
        val dh = d.intrinsicHeight.toFloat()
        if (vw <= 0f || vh <= 0f || dw <= 0f || dh <= 0f) return

        drawMatrix.reset()
        val scale = min(vw / dw, vh / dh)
        baseScale = scale
        currentScale = scale

        val dx = (vw - dw * scale) * 0.5f
        val dy = (vh - dh * scale) * 0.5f
        drawMatrix.postScale(scale, scale)
        drawMatrix.postTranslate(dx, dy)
        imageMatrix = drawMatrix
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        fitBitmapToCenter()
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        doubleTapDetector.onTouchEvent(event)
        scaleDetector.onTouchEvent(event)

        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                lastTouchX = event.x
                lastTouchY = event.y
                isDragging = true
            }
            MotionEvent.ACTION_MOVE -> {
                if (isDragging && !scaleDetector.isInProgress && event.pointerCount == 1) {
                    val dx = event.x - lastTouchX
                    val dy = event.y - lastTouchY
                    drawMatrix.postTranslate(dx, dy)
                    imageMatrix = drawMatrix
                    lastTouchX = event.x
                    lastTouchY = event.y
                }
            }
            MotionEvent.ACTION_POINTER_UP -> {
                val remainingIndex = if (event.actionIndex == 0) 1 else 0
                if (remainingIndex < event.pointerCount) {
                    lastTouchX = event.getX(remainingIndex)
                    lastTouchY = event.getY(remainingIndex)
                }
            }
            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                isDragging = false
            }
        }
        return max(1, event.pointerCount) >= 1
    }
}
